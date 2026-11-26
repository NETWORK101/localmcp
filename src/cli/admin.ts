import { existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { loadConfig, type LocalMcpConfig } from '../config/schema.js';
import { profileDirFor } from '../browser/manager.js';
import { interactDecision, sessionScope } from '../security/policy.js';
import { addSite, loadSites, removeSite, sitesPath } from '../security/sites.js';
import { readAudit } from '../security/audit.js';
import { VERSION } from '../version.js';

/**
 * Operator commands: what can the agent reach as me, and what did it do?
 *
 *   localmcp sites [list]          the signed-in sites for the current engine's profile
 *   localmcp sites add <host>      "dashboard.stripe.com" or "*.stripe.com"
 *   localmcp sites remove <host>
 *   localmcp audit [--tail N] [--json]
 *   localmcp doctor [--json]       security posture; exits 1 when something needs fixing
 */

function profilePath(config: LocalMcpConfig): string {
  return profileDirFor(config.browser.engine, config.browser.profileDir);
}

export function runSites(argv: string[], config: LocalMcpConfig = loadConfig()): number {
  const [sub = 'list', target] = argv;
  const dir = profilePath(config);
  if (sub === 'add' || sub === 'remove') {
    if (!target) {
      console.error(`Usage: localmcp sites ${sub} <host>   e.g. dashboard.stripe.com or "*.stripe.com"`);
      return 1;
    }
    if (sub === 'add') {
      const host = addSite(dir, target, 'manual');
      if (!host) {
        console.error(
          target.trim().startsWith('*.')
            ? `"${target}" would cover sites run by other people (a public suffix). Use a narrower pattern such as "*.stripe.com".`
            : `"${target}" isn't a host name or http(s) URL.`
        );
        return 1;
      }
      console.log(`Added ${host}. A running server picks it up on its next call.`);
      return 0;
    }
    if (!removeSite(dir, target)) {
      console.error(`${target} isn't in ${sitesPath(dir)}.`);
      return 1;
    }
    console.log(`Removed ${target}; it now opens signed out. Its cookies stay in the profile until you sign out on the site.`);
    return 0;
  }
  if (sub !== 'list') {
    console.error(`Unknown subcommand "${sub}". Use: localmcp sites [list|add <host>|remove <host>]`);
    return 1;
  }
  const sites = loadSites(dir);
  if (!existsSync(dir)) console.log('No saved login profile. Run `localmcp login <url>` to create one.');
  else if (sites.length === 0) console.log('The saved profile has no site list, so every page opens signed in. Add sites with `localmcp sites add <host>`.');
  for (const s of sites) console.log(`${s.host}\t${s.via}\t${s.addedAt}`);
  return 0;
}

export function runAudit(argv: string[], config: LocalMcpConfig = loadConfig()): number {
  const json = argv.includes('--json');
  const i = argv.indexOf('--tail');
  const tail = i !== -1 ? Number(argv[i + 1]) || 50 : 50;
  if (!config.audit.enabled) {
    console.log('Auditing is off (audit.enabled: false).');
    return 0;
  }
  const entries = readAudit(config.audit.path, tail);
  if (json) {
    console.log(JSON.stringify(entries, null, 2));
    return 0;
  }
  if (entries.length === 0) console.log(`No entries in ${config.audit.path} yet.`);
  for (const e of entries) {
    const where = e.host ? `${e.host}${e.path ?? ''}` : '-';
    const extra = [e.redactions ? `${e.redactions} redacted` : '', e.reason ?? ''].filter(Boolean).join(' · ');
    console.log(`${e.ts}  ${e.outcome.padEnd(7)} ${e.session.padEnd(9)} ${e.tool.padEnd(10)} ${where}${extra ? `  (${extra})` : ''}`);
  }
  return 0;
}

export interface Finding {
  level: 'ok' | 'warn' | 'risk';
  text: string;
}

/** Posture checks, pure over config + the filesystem, so tests can drive them. */
export function postureFindings(config: LocalMcpConfig): Finding[] {
  const out: Finding[] = [];
  const scope = sessionScope(config.browser);
  const sites = loadSites(profilePath(config));
  const { policy } = config;

  if (scope === 'none') out.push({ level: 'ok', text: 'No signed-in session: every page opens with no cookies.' });
  if (scope === 'scoped') out.push({ level: 'ok', text: `Signed in, scoped to: ${sites.map((s) => s.host).join(', ')}. Other pages open signed out.` });
  if (scope === 'all-hosts') {
    const how = config.browser.cdpEndpoint ? `attached to your browser at ${config.browser.cdpEndpoint}` : 'saved profile has no site list';
    out.push({
      level: policy.allow.length ? 'warn' : 'risk',
      text: `Every page opens signed in (${how}).${policy.allow.length ? ` policy.allow limits it to ${policy.allow.join(', ')}.` : ' Run `localmcp sites add <host>` or set policy.allow.'}`,
    });
  }

  const interact = interactDecision(config, scope);
  if (policy.allowInteract === true && scope !== 'none') {
    out.push({ level: 'risk', text: 'interact is on with your signed-in session (policy.allowInteract: true): the agent can click and submit as you.' });
  } else {
    out.push({ level: 'ok', text: interact.allowed ? (scope === 'scoped' ? 'interact: anonymous pages only.' : 'interact: on (no signed-in session).') : 'interact: off.' });
  }

  if (scope !== 'none') {
    out.push(
      policy.egress === 'open'
        ? { level: 'risk', text: 'policy.egress is "open": after a signed-in read the agent may open any host, the usual exfiltration path.' }
        : { level: 'ok', text: `After a signed-in read, new hosts are ${policy.egress === 'block' ? 'refused' : 'confirmed with you first'}.` }
    );
  }
  out.push(
    policy.redactSecrets === false
      ? { level: 'warn', text: 'policy.redactSecrets is off: API keys and card numbers on pages reach the model.' }
      : { level: 'ok', text: 'Secrets on pages are redacted before the model sees them.' }
  );
  if (policy.allowFileUrls) out.push({ level: 'warn', text: 'file:// URLs are allowed: the agent can read local files through the browser.' });
  out.push(
    config.audit.enabled
      ? { level: 'ok', text: `Audit log: ${config.audit.path}` }
      : { level: 'warn', text: 'Audit log is off (audit.enabled: false).' }
  );
  return out;
}

export function runDoctor(argv: string[], config: LocalMcpConfig = loadConfig()): number {
  const findings = postureFindings(config);
  const risky = findings.some((f) => f.level === 'risk');
  if (argv.includes('--json')) {
    console.log(JSON.stringify({ version: VERSION, findings }, null, 2));
    return risky ? 1 : 0;
  }
  const mark = { ok: '✓', warn: '!', risk: '✗' } as const;
  const configs = [join(homedir(), '.config', 'localmcp', 'config.json'), join(process.cwd(), '.localmcp.json')].filter(existsSync);
  console.log(`localmcp ${VERSION} · ${config.browser.engine}${config.browser.channel ? ` (${config.browser.channel})` : ''}`);
  console.log(`Config: ${configs.length ? configs.join(', ') : 'defaults'}\n`);
  for (const f of findings) console.log(`${mark[f.level]} ${f.text}`);
  return risky ? 1 : 0;
}
