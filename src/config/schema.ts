import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

/**
 * How the browser keeps (or doesn't keep) session state between calls.
 * - "auto":       use the persistent profile if `localmcp login` has created one, else ephemeral
 * - "persistent": always use the persistent profile at `profileDir`
 * - "ephemeral":  fresh incognito-style context per call (no cookies survive)
 */
export type ProfileMode = 'auto' | 'persistent' | 'ephemeral';

/** Browser engine. Firefox and WebKit (Safari's engine) ship with Playwright alongside Chromium. */
export type BrowserEngine = 'chromium' | 'firefox' | 'webkit';
export const ENGINES: BrowserEngine[] = ['chromium', 'firefox', 'webkit'];

export interface LocalMcpConfig {
  browser: {
    timeout: number;
    headless: boolean;
    engine: BrowserEngine;
    /** Chromium only: use an installed branded browser — "chrome", "msedge", "chrome-beta", "msedge-dev"… */
    channel?: string;
    profile: ProfileMode;
    profileDir: string;
    /** Attach to an already-running Chromium-based browser (Chrome, Edge, Brave, Arc…) e.g. http://localhost:9222. */
    cdpEndpoint?: string;
  };
  distill: {
    maxTokens: number;
    includeLinks: boolean;
    includeImages: boolean;
    /** Use markdown the publisher serves for agents (text/markdown alternate or Accept: text/markdown). */
    publisherMarkdown: boolean;
  };
  policy: {
    /** Host globs the agent may visit. Empty = any host. e.g. ["*.stripe.com", "localhost:*"] */
    allow: string[];
    /** Host globs that are always refused, checked before `allow`. */
    deny: string[];
    /**
     * Whether the agent may click and type (`interact`).
     * - "auto" (default): allowed in throwaway sessions, off while a signed-in session is in use
     *   (persistent profile or an attached browser) — "signed in, but scoped".
     * - true: always allowed. false: never (read-only mode).
     */
    allowInteract: boolean | 'auto';
    /** Allow file:// URLs. Off by default — local files are rarely what an agent should read via a browser. */
    allowFileUrls: boolean;
    /**
     * What may happen after the agent has read a page with your signed-in session.
     * A prompt-injected page can tell the agent to carry what it read to another host in a URL.
     * - "confirm" (default): opening a host that isn't a signed-in site, in `allow`, or already
     *   approved asks you first (MCP elicitation); clients that can't ask get a refusal.
     * - "block": refuse such hosts outright. "open": no check (the 0.3 behaviour).
     */
    egress: 'confirm' | 'block' | 'open';
    /** Replace API keys, tokens, private keys and card numbers in tool output. On by default. */
    redactSecrets: boolean;
  };
  audit: {
    /** Append one JSON line per tool call (host, path without query, session, outcome) to `path`. */
    enabled: boolean;
    path: string;
  };
  limits: {
    maxSessionsPerDay: number;
    maxTokensPerDay: number;
  };
}

/** @deprecated kept for API compatibility with <=0.1.x imports */
export type HeadlessDevConfig = LocalMcpConfig;

/** ~/.localmcp — or the pre-rename ~/.browsermcp when only that exists, so saved logins and usage carry over. */
export function resolveStateDir(home: string = homedir()): string {
  const next = join(home, '.localmcp');
  const prev = join(home, '.browsermcp');
  return existsSync(next) || !existsSync(prev) ? next : prev;
}
/** LOCALMCP_HOME relocates all state (profile, usage, audit log), e.g. per project or in tests. */
export const STATE_DIR = process.env.LOCALMCP_HOME || resolveStateDir();

export const DEFAULT_CONFIG: LocalMcpConfig = {
  browser: {
    timeout: 30000,
    headless: true,
    engine: 'chromium',
    profile: 'auto',
    profileDir: join(STATE_DIR, 'profile'),
  },
  distill: { maxTokens: 4000, includeLinks: true, includeImages: false, publisherMarkdown: true },
  policy: { allow: [], deny: [], allowInteract: 'auto', allowFileUrls: false, egress: 'confirm', redactSecrets: true },
  audit: { enabled: true, path: join(STATE_DIR, 'audit.jsonl') },
  limits: { maxSessionsPerDay: 100, maxTokensPerDay: 1_000_000 },
};

type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? Partial<T[K]> : T[K] };

function deepMerge(base: LocalMcpConfig, override: DeepPartial<LocalMcpConfig>): LocalMcpConfig {
  return {
    browser: { ...base.browser, ...override.browser },
    distill: { ...base.distill, ...override.distill },
    policy: { ...base.policy, ...override.policy },
    limits: { ...base.limits, ...override.limits },
    audit: { ...base.audit, ...override.audit },
  };
}

function tryLoad(filePath: string): DeepPartial<LocalMcpConfig> | null {
  if (!existsSync(filePath)) return null;
  try {
    return JSON.parse(readFileSync(filePath, 'utf-8')) as DeepPartial<LocalMcpConfig>;
  } catch (err) {
    // A broken config should be loud, not silently ignored — but must not crash the stdio server.
    console.error(`[localmcp] Ignoring invalid JSON in ${filePath}: ${(err as Error).message}`);
    return null;
  }
}

function firstExisting(...paths: string[]): string {
  return paths.find((p) => existsSync(p)) ?? paths[0];
}

export function loadConfig(opts: { cwd?: string; home?: string } = {}): LocalMcpConfig {
  const home = opts.home ?? homedir();
  const cwd = opts.cwd ?? process.cwd();
  // Resolution order: defaults ← ~/.config/localmcp/config.json ← .localmcp.json in CWD.
  // The pre-rename names (browsermcp) are still read when the new ones don't exist.
  const globalPath = firstExisting(
    join(home, '.config', 'localmcp', 'config.json'),
    join(home, '.config', 'browsermcp', 'config.json')
  );
  const localPath = firstExisting(join(cwd, '.localmcp.json'), join(cwd, '.browsermcp.json'));

  let config = deepMerge(DEFAULT_CONFIG, {});

  const global = tryLoad(globalPath);
  if (global) config = deepMerge(config, global);

  const local = tryLoad(localPath);
  if (local) config = deepMerge(config, local);

  return config;
}
