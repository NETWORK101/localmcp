import { BrowserManager } from './browser/manager.js';
import { handleBrowse } from './tools/browse.js';
import { handleExtract } from './tools/extract.js';
import { handleLinks } from './tools/links.js';
import { handleScreenshot } from './tools/screenshot.js';
import { handleInteract } from './tools/interact.js';
import { errorResult, type ToolContext, type ToolResult } from './tools/common.js';
import { UsageTracker } from './cost/tracker.js';
import { CircuitBreaker } from './cost/circuit-breaker.js';
import type { LocalMcpConfig } from './config/schema.js';
import {
  checkUrl,
  interactDecision,
  isDeniedRequest,
  INTERACT_SIGNED_IN_REASON,
  type InteractDecision,
} from './security/policy.js';
import { EgressGuard } from './security/egress.js';
import { AuditLog, urlParts, type AuditEntry } from './security/audit.js';
import { describeRedactions, redactDeep, redactSecrets } from './security/redact.js';

export const TOOL_NAMES = ['browse', 'extract', 'links', 'screenshot', 'interact'] as const;

/**
 * Everything a tool call needs, shared by the MCP server and the CLI so both enforce the same
 * policy, limits, fencing and usage tracking.
 */
export interface Runtime {
  config: LocalMcpConfig;
  tracker: UsageTracker;
  browserManager: BrowserManager;
  breaker: CircuitBreaker;
  /** Resolved once: the session mode doesn't change while a server or CLI command runs. */
  interact: InteractDecision;
  egress: EgressGuard;
  audit: AuditLog;
  /** The one-time warning about an unscoped signed-in session has been shown. */
  postureShown: boolean;
}

/** Hooks a transport can provide. `confirm` asks the human (MCP elicitation); absent = can't ask. */
export interface RunHooks extends Pick<ToolContext, 'sample'> {
  progress?: ToolContext['progress'];
  confirm?: (message: string) => Promise<boolean>;
}

export function createRuntime(config: LocalMcpConfig, tracker: UsageTracker = new UsageTracker()): Runtime {
  // The guard and the manager reference each other: the guard asks which sites are signed in,
  // the manager asks the guard about every navigation hop once it is armed.
  let browserManager: BrowserManager;
  const egress = new EgressGuard(
    config.policy,
    () => browserManager.signedInSites,
    () => browserManager.scope
  );
  browserManager = new BrowserManager({
    ...config.browser,
    blockRequest: config.policy.deny.length ? (url) => isDeniedRequest(url, config.policy) : undefined,
    navigationGuard: {
      active: () => egress.armed,
      check: (url) => {
        const d = egress.check(url);
        if (d.ok) return null;
        return (
          `a redirect or script tried to take the page to ${d.host} after a signed-in read of ${egress.signedInSource}. ` +
          `That's how an injected link carries data off a site, so it was stopped before the request left. ` +
          `If ${d.host} is expected (a sign-in provider, say), add "${new URL(url).hostname}" to policy.allow.`
        );
      },
    },
  });
  return {
    config,
    tracker,
    browserManager,
    breaker: new CircuitBreaker(tracker, config.limits),
    interact: interactDecision(config, browserManager.scope),
    egress,
    audit: new AuditLog(config.audit?.enabled === false ? null : (config.audit?.path ?? null)),
    postureShown: false,
  };
}

/** Shown once per run when every host opens with the user's cookies and nothing narrows it. */
function postureNotice(rt: Runtime): string | null {
  if (rt.postureShown || rt.browserManager.scope !== 'all-hosts' || rt.config.policy.allow.length > 0) return null;
  rt.postureShown = true;
  return rt.config.browser.cdpEndpoint
    ? 'localmcp is attached to your own browser, so every page opens with your cookies. ' +
        'Set policy.allow in .localmcp.json to the hosts this agent needs.'
    : 'Your saved login profile predates localmcp 0.4 and has no site list, so every page opens signed in. ' +
        'Run `localmcp sites add <host>` for each site you signed in to: other pages will then open without your cookies.';
}

function redactResult(result: ToolResult): number {
  const residual: Record<string, number> = {};
  for (const item of result.content) {
    if (item.type === 'text') item.text = redactSecrets(item.text).text;
  }
  if (result.structuredContent) result.structuredContent = redactDeep(result.structuredContent, residual);
  // distill() already redacted page text before truncation; count every stub in what goes out.
  const found: Record<string, number> = {};
  for (const item of result.content) {
    if (item.type !== 'text') continue;
    for (const m of item.text.matchAll(/\[redacted ([a-z-]+?)(?:…\d{4})?\]/g)) found[m[1]] = (found[m[1]] ?? 0) + 1;
  }
  const note = describeRedactions(found);
  if (note) result.content.push({ type: 'text', text: `_Note: ${note}_` });
  return Object.values(found).reduce((a, b) => a + b, 0);
}

function estimateTokensFromResult(result: ToolResult): number {
  let chars = 0;
  for (const item of result.content) {
    if (item.type === 'text') chars += item.text.length;
  }
  return Math.ceil(chars / 4);
}

/** Validate, police, dispatch and record one tool call. */
export async function runTool(
  rt: Runtime,
  name: string,
  rawArgs: Record<string, unknown> | undefined,
  hooks: RunHooks = {}
): Promise<ToolResult> {
  const args = { ...(rawArgs ?? {}) } as Record<string, any>;
  const { host, path } = urlParts(args.url);
  const audit = (entry: Partial<AuditEntry> & Pick<AuditEntry, 'outcome'>) =>
    rt.audit.write({ tool: name, host, path, session: 'none', ...entry });
  const refuse = (message: string): ToolResult => {
    // Reasons can echo the requested URL; drop query strings and fragments as the path field does.
    audit({ outcome: 'blocked', reason: message.replace(/[?#][^\s"')]*/g, '?…').slice(0, 200) });
    return errorResult(message);
  };

  // `watch` was folded into `browse({ diff: true })` in 0.2 — keep old prompts working.
  const tool = name === 'watch' ? 'browse' : name;
  if (name === 'watch') args.diff = true;

  if (!(TOOL_NAMES as readonly string[]).includes(tool)) {
    return errorResult(`Unknown tool: ${name}`);
  }
  if (tool === 'interact' && !rt.interact.allowed) {
    return refuse(rt.interact.reason);
  }
  if (typeof args.url !== 'string') {
    return errorResult(`"${tool}" requires a "url" string.`);
  }
  const decision = checkUrl(args.url, rt.config.policy);
  if (!decision.ok) {
    return refuse(`Blocked by localmcp policy: ${decision.reason}`);
  }
  const route = rt.browserManager.routeFor(args.url);
  if (tool === 'interact' && route === 'signed-in' && rt.config.policy.allowInteract === 'auto') {
    return refuse(INTERACT_SIGNED_IN_REASON);
  }
  const egress = rt.egress.check(args.url);
  if (!egress.ok) {
    const approved =
      egress.confirmable && hooks.confirm
        ? await hooks
            .confirm(
              `Your agent read ${rt.egress.signedInSource} with your signed-in session and now wants to open ` +
                `${egress.host} (${tool}). A page can trick an agent into sending what it read to another site ` +
                `in the URL. Allow ${egress.host} for the rest of this session?`
            )
            .catch(() => false)
        : false;
    if (!approved) {
      return refuse(
        hooks.confirm && egress.confirmable
          ? `${egress.host} wasn't opened: you declined it after a signed-in read of ${rt.egress.signedInSource}.`
          : egress.reason
      );
    }
    rt.egress.approve(egress.host);
  }
  const check = rt.breaker.check();
  if (!check.allowed) {
    return refuse(check.message!);
  }
  // Arm before the call runs, so a concurrent call can't leave while this read is in flight.
  if (route === 'signed-in') rt.egress.arm(args.url);

  const ctx: ToolContext = {
    config: rt.config,
    tracker: rt.tracker,
    progress: hooks.progress ?? (async () => {}),
    sample: hooks.sample,
  };

  const startTime = Date.now();
  let result: ToolResult;
  switch (tool) {
    case 'browse':
      result = await handleBrowse(args as any, rt.browserManager, ctx);
      break;
    case 'extract':
      result = await handleExtract(args as any, rt.browserManager, ctx);
      break;
    case 'links':
      result = await handleLinks(args as any, rt.browserManager, ctx);
      break;
    case 'screenshot':
      result = await handleScreenshot(args as any, rt.browserManager, ctx);
      break;
    default:
      result = await handleInteract(args as any, rt.browserManager, ctx);
  }

  // Ask again after the call: a locked profile degrades signed-in routes to anonymous.
  const signedIn = rt.browserManager.routeFor(args.url) === 'signed-in';

  const redactions = rt.config.policy.redactSecrets === false ? 0 : redactResult(result);
  if (signedIn && tool === 'screenshot' && !result.isError) {
    result.content.push({
      type: 'text',
      text: '_Note: this screenshot was taken with your signed-in session. Images are not redacted._',
    });
  }
  const posture = postureNotice(rt);
  if (posture) result.content.push({ type: 'text', text: `_Note: ${posture}_` });

  const tokens = estimateTokensFromResult(result);
  const ms = Date.now() - startTime;
  rt.tracker.record(name, tokens, ms, args.url);
  audit({
    outcome: result.isError ? 'error' : 'ok',
    session: signedIn ? 'signed-in' : 'anonymous',
    tokens,
    ms,
    ...(redactions ? { redactions } : {}),
  });
  return result;
}
