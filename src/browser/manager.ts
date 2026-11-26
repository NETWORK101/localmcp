import { chromium, firefox, webkit, Browser, BrowserContext, BrowserType, Page } from "playwright";
import { existsSync } from "fs";
import { PageWrapper } from "./page.js";
import type { BrowserEngine, ProfileMode } from "../config/schema.js";
import { isSignedInSite, loadSites, type SiteEntry } from "../security/sites.js";

export interface BrowserManagerConfig {
  timeout: number;
  headless: boolean;
  /** Defaults to "ephemeral" when constructed directly (tests, library use). */
  profile: ProfileMode;
  engine?: BrowserEngine;
  /** Chromium only — an installed branded build such as "chrome" or "msedge". */
  channel?: string;
  /** Abort any request (navigation, subresource, iframe, fetch) for which this returns true. */
  blockRequest?: (url: string) => boolean;
  profileDir?: string;
  cdpEndpoint?: string;
  /** Signed-in sites for the persistent profile. Defaults to the profile's localmcp-sites.json. */
  sites?: SiteEntry[];
}

export interface GetPageOptions {
  timeout?: number;
  /** CSS selector to wait for after load — useful for SPAs that render late. */
  waitFor?: string;
}

const DEFAULT_BROWSER_CONFIG: BrowserManagerConfig = { timeout: 30_000, headless: true, profile: "ephemeral" };

/** Upper bound on how long we wait for the network to settle after DOMContentLoaded. */
const SETTLE_MS = 2_500;

export type SessionKind = "ephemeral" | "persistent" | "cdp";

const ENGINE_TYPES: Record<BrowserEngine, BrowserType> = { chromium, firefox, webkit };

export function browserTypeFor(engine: BrowserEngine = "chromium"): BrowserType {
  const t = ENGINE_TYPES[engine];
  if (!t) throw new Error(`Unknown browser engine "${engine}". Use one of: chromium, firefox, webkit.`);
  return t;
}

/**
 * Engines can't share a profile directory (Chromium, Gecko and WebKit store state differently),
 * so non-Chromium engines get a sibling directory: ~/.localmcp/profile-firefox, …-webkit.
 */
export function profileDirFor(engine: BrowserEngine = "chromium", profileDir: string): string {
  return engine === "chromium" ? profileDir : `${profileDir}-${engine}`;
}

/** Launch options shared by the server and `localmcp login`. */
export function launchOptions(engine: BrowserEngine = "chromium", channel?: string): { channel?: string } {
  if (channel && engine !== "chromium") {
    throw new Error(`browser.channel "${channel}" only applies to the chromium engine (got "${engine}").`);
  }
  return channel ? { channel } : {};
}

let signalHandlersInstalled = false;
const liveManagers = new Set<BrowserManager>();

/**
 * How signed-in state is scoped for this manager.
 * - "none":      no saved profile or attached browser — every page is anonymous.
 * - "scoped":    a saved profile with registered sites; only those hosts open with it.
 * - "all-hosts": an attached browser (CDP), or a pre-0.4 profile with no site list —
 *                every page opens with the user's cookies.
 */
export type SessionScope = "none" | "scoped" | "all-hosts";
export type Route = "signed-in" | "anonymous";

export class BrowserManager {
  private browser: Browser | null = null;
  /** Shared, long-lived context for persistent-profile and CDP modes. */
  private sharedContext: BrowserContext | null = null;
  private cdpBrowser: Browser | null = null;
  private contexts: Set<BrowserContext> = new Set();
  private config: BrowserManagerConfig;
  private launchingShared: Promise<void> | null = null;
  private launchingBrowser: Promise<void> | null = null;
  private sharedKind: "persistent" | "cdp" | null = null;
  /** Set when the persistent profile couldn't be opened (locked by another process). */
  private persistentFailed = false;
  private notices: string[] = [];
  private sites: SiteEntry[];

  constructor(config?: Partial<BrowserManagerConfig>) {
    this.config = { ...DEFAULT_BROWSER_CONFIG, ...config };
    this.sites = this.config.sites ?? (this.profilePath ? loadSites(this.profilePath) : []);
    liveManagers.add(this);
    if (!signalHandlersInstalled) {
      signalHandlersInstalled = true;
      const cleanupAll = () => {
        Promise.allSettled([...liveManagers].map((m) => m.cleanup())).finally(() => process.exit(0));
      };
      process.once("SIGINT", cleanupAll);
      process.once("SIGTERM", cleanupAll);
    }
  }

  /** The anonymous browser (ephemeral contexts), once launched. */
  getBrowserInstance(): Browser | null {
    return this.browser;
  }

  /** The mode of the most capable session opened so far (null until the first page). */
  get sessionKind(): SessionKind | null {
    return this.sharedKind ?? (this.browser ? "ephemeral" : null);
  }

  get signedInSites(): readonly SiteEntry[] {
    return this.sites;
  }

  get scope(): SessionScope {
    if (this.config.cdpEndpoint) return "all-hosts";
    if (!this.wantsPersistent()) return "none";
    return this.sites.length > 0 ? "scoped" : "all-hosts";
  }

  /** Which session a URL would open in. Pure: decided from config, sites and earlier failures. */
  routeFor(url: string): Route {
    const scope = this.scope;
    if (scope === "none") return "anonymous";
    if (this.config.cdpEndpoint) return "signed-in";
    if (this.persistentFailed) return "anonymous";
    if (scope === "all-hosts") return "signed-in";
    return isSignedInSite(url, this.sites) ? "signed-in" : "anonymous";
  }

  /** One-time notices (e.g. "profile locked, fell back to ephemeral") for surfacing to the agent. */
  drainNotices(): string[] {
    const n = this.notices;
    this.notices = [];
    return n;
  }

  private get profilePath(): string | undefined {
    return this.config.profileDir ? profileDirFor(this.config.engine, this.config.profileDir) : undefined;
  }

  private wantsPersistent(): boolean {
    const { profile } = this.config;
    if (profile === "persistent") return true;
    if (profile === "auto") return !!this.profilePath && existsSync(this.profilePath);
    return false;
  }

  private async launchShared(): Promise<void> {
    const engine = this.config.engine ?? "chromium";
    if (this.config.cdpEndpoint) {
      if (engine !== "chromium") {
        throw new Error(`cdpEndpoint attaches to Chromium-based browsers only; browser.engine is "${engine}".`);
      }
      // Attach to the user's own Chrome: real cookies, real extensions, real sessions.
      this.cdpBrowser = await chromium.connectOverCDP(this.config.cdpEndpoint);
      this.sharedContext = this.cdpBrowser.contexts()[0] ?? (await this.cdpBrowser.newContext());
      this.sharedKind = "cdp";
      return;
    }
    try {
      this.sharedContext = await browserTypeFor(engine).launchPersistentContext(this.profilePath!, {
        headless: this.config.headless,
        ...launchOptions(engine, this.config.channel),
      });
      this.sharedKind = "persistent";
    } catch (err) {
      // Chromium locks a profile to one process. If another localmcp (or `localmcp login`)
      // holds it, degrade to anonymous rather than failing every call.
      this.persistentFailed = true;
      this.notices.push(
        `Persistent profile unavailable (${(err as Error).message.split("\n")[0]}). ` +
          `Using an ephemeral session — authenticated pages may show a login screen.`
      );
    }
  }

  private async launchBrowser(): Promise<void> {
    const engine = this.config.engine ?? "chromium";
    this.browser = await browserTypeFor(engine).launch({
      headless: this.config.headless,
      ...launchOptions(engine, this.config.channel),
    });
  }

  // Concurrent tool calls must not race to launch two browsers.
  private async ensureShared(): Promise<void> {
    if (this.sharedContext || this.persistentFailed) return;
    this.launchingShared ??= this.launchShared().finally(() => {
      this.launchingShared = null;
    });
    await this.launchingShared;
  }

  private async ensureBrowser(): Promise<void> {
    if (this.browser) return;
    this.launchingBrowser ??= this.launchBrowser().finally(() => {
      this.launchingBrowser = null;
    });
    await this.launchingBrowser;
  }

  async getPage(url: string, opts?: GetPageOptions): Promise<PageWrapper> {
    const timeout = opts?.timeout ?? this.config.timeout;

    let route = this.routeFor(url);
    if (route === "signed-in") {
      await this.ensureShared();
      if (!this.sharedContext) route = "anonymous";
    }

    let page: Page;
    let ownedContext: BrowserContext | null = null;
    if (route === "signed-in") {
      page = await this.sharedContext!.newPage();
    } else {
      await this.ensureBrowser();
      ownedContext = await this.browser!.newContext();
      this.contexts.add(ownedContext);
      ownedContext.once("close", () => this.contexts.delete(ownedContext!));
      page = await ownedContext.newPage();
    }

    try {
      if (this.config.blockRequest) {
        // Page-level (not context-level) routing: in CDP mode the context is the user's own
        // browser, and their other tabs must not be intercepted.
        const block = this.config.blockRequest;
        await page.route('**/*', (r) =>
          block(r.request().url()) ? r.abort('blockedbyclient') : r.continue()
        );
      }
      await navigate(page, url, timeout, opts?.waitFor);
    } catch (err) {
      await (ownedContext ? ownedContext.close() : page.close()).catch(() => {});
      throw err;
    }

    return new PageWrapper(page, ownedContext, timeout, route === "signed-in");
  }

  async cleanup(): Promise<void> {
    for (const context of this.contexts) {
      await context.close().catch(() => {});
    }
    this.contexts.clear();

    // In CDP mode the browser belongs to the user — disconnect, never close their context.
    if (this.sharedContext && this.sharedKind !== "cdp") {
      await this.sharedContext.close().catch(() => {});
    }
    this.sharedContext = null;
    if (this.cdpBrowser) {
      await this.cdpBrowser.close().catch(() => {});
      this.cdpBrowser = null;
    }

    if (this.browser) {
      await this.browser.close().catch(() => {});
      this.browser = null;
    }
    this.sharedKind = null;
    this.persistentFailed = false;
    liveManagers.delete(this);
  }
}

/**
 * Navigate and give client-rendered apps a bounded chance to finish rendering.
 * `load` alone fires before most SPAs fetch their data; full `networkidle` can hang forever
 * on pages with analytics beacons or websockets. So: DOMContentLoaded, then a capped settle.
 */
export async function navigate(page: Page, url: string, timeout: number, waitFor?: string): Promise<void> {
  await page.goto(url, { timeout, waitUntil: "domcontentloaded" });
  await page.waitForLoadState("networkidle", { timeout: Math.min(SETTLE_MS, timeout) }).catch(() => {});
  if (waitFor) {
    await page.waitForSelector(waitFor, { timeout: Math.min(10_000, timeout) });
  }
}
