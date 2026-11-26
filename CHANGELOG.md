# Changelog

## 0.4.0 — 2026-11-25

Signed in, but scoped, now covers *where* the agent reads as you, not just whether it can click.

### Security
- **Signed-in sites.** `localmcp login <url>` records that host in `localmcp-sites.json` inside the profile. Only those hosts open with the saved profile; every other URL opens in a throwaway context with no cookies. In 0.3 a third-party page opened in the profile could make credentialed requests to your signed-in sites; a regression test now shows 0.3's exposure and 0.4's fix side by side.
- **Egress guard (`policy.egress`, default `"confirm"`).** Once a call opens a page with your session, opening a host that isn't a signed-in site, in `policy.allow`, or approved by you asks you first through MCP elicitation. Hosts the agent has merely read are never trusted, since the injected page is usually read first. The guard arms when the signed-in call *starts*, so concurrent calls can't slip out, and it checks every main-frame hop: server redirects (walked hop by hop before the browser follows them), script navigation and form submits. An open redirect on a signed-in site can't carry data off. The navigation check fails closed (an unverifiable or over-long redirect chain is blocked), form posts are sent once and their redirects checked, and pages can't open popups or `target=_blank` windows the check wouldn't cover. Clients without elicitation get a refusal naming the fix. `"block"` refuses outright; `"open"` restores 0.3.
- **Redaction (`policy.redactSecrets`, default on).** API keys (Stripe, OpenAI, Anthropic, GitHub, npm, Slack, AWS, Google), JWTs, private key blocks and card-shaped, Luhn-valid numbers are replaced with labelled stubs in text, `structuredContent`, sampling prompts and stored diff snapshots. Pages are redacted before the token budget cuts them, so a truncated key can't slip through, and the scanner stays linear on hostile input. Screenshots taken with your session carry a note that images aren't redacted.
- **Audit log.** `~/.localmcp/audit.jsonl` (mode 600) gets one line per call, refusals included: tool, host, path, session, outcome, redactions. Query strings and fragments are never logged, and `usage.db` now stores a hash in their place too.
- **`interact` per host.** With a scoped profile, `interact` stays listed and works on anonymous pages; it's refused on signed-in ones unless `allowInteract: true`.
- **Supply chain.** Releases publish with npm Trusted Publishing (OIDC, provenance) instead of a long-lived `NPM_TOKEN`, then publish `server.json` to the MCP registry. Actions are pinned to commit SHAs, CI runs `npm audit signatures` and fails on high/critical advisories, and Dependabot proposes updates after a 7-day cooldown.

### Added
- `localmcp sites [list|add <host>|remove <host>]`, `localmcp doctor` (posture check, exit 1 on a risky setup), `localmcp audit [--tail N] [--json]`.
- `LOCALMCP_HOME` relocates all state (profile, usage, audit).

### Changed
- Playwright 1.65, MCP SDK 1.32, better-sqlite3 12: `npm audit --omit=dev` is clean (10 findings in 0.3.1, 1 critical). CI tests Node 20, 22 and 24 on ubuntu-24.04 (`ubuntu-latest` moved to 26.04, which Playwright 1.48 refused).
- `server.json` points at the live site instead of the parked localmcp.dev.

### Upgrading
- **Profiles created before 0.4** have no site list, so every page still opens signed in, and each run says so once. Because every read is then signed in, the egress guard asks before each new host after the first call, and refuses on clients without elicitation. Run `localmcp sites add <host>` for the sites you signed in to (or `localmcp login <url>` again) and only those hosts stay signed in. `localmcp doctor` checks the result.
- **An attached browser (`cdpEndpoint`)** behaves the same way. Set `policy.allow` to the hosts the agent needs.
- A redirect from a signed-in site to a host outside the site list (an expired session bouncing to a sign-in provider, say) is stopped after a signed-in read. Add that host to `policy.allow` if it's expected.
- Diff snapshots stored by 0.3 are keyed by the raw URL, so the first `diff: true` read of each URL after upgrading takes a new baseline.
- `localmcp sites add/remove` takes effect without restarting the server. Wildcards over public suffixes (`*.com`, `*.co.uk`, `*.github.io`) are refused.

## 0.3.1 — 2026-10-12

First release on npm. The package ships under the **`@localmcp_serv`** scope: `npx -y @localmcp_serv/localmcp`; Claude Code: `claude mcp add localmcp -- npx -y @localmcp_serv/localmcp`. (0.3.0's notes named `@network101/localmcp`; that scope was never registered on npm, so nothing was published under it.) The MCP registry name stays `io.github.network101/localmcp`, which follows the GitHub org.

### Fixed
- `localmcp --version` and the MCP server's `serverInfo.version` reported `0.0.0`: the version reader only recognised a manifest named `localmcp`, not `@network101/localmcp`. It accepts both.

## 0.3.0 — 2026-10-01

### Renamed
- The package is now **`@network101/localmcp`** (previously `browsermcpai`, and `headlessdev` before that). Plain `localmcp` is too close to the existing `local-mcp` on npm, so it ships under the NETWORK101 scope. The command is still `localmcp`. MCP client configs: `npx -y @network101/localmcp`; Claude Code: `claude mcp add localmcp -- npx -y @network101/localmcp`.
- Everything from the old name keeps working: `.browsermcp.json` and `~/.config/browsermcp/config.json` are read when the new files don't exist, `~/.browsermcp` (saved logins, usage) is used when `~/.localmcp` doesn't exist, and `BROWSERMCP_NO_LIMIT` still overrides the circuit breaker. New names: `.localmcp.json`, `~/.config/localmcp/config.json`, `~/.localmcp`, `LOCALMCP_NO_LIMIT`.

### Added
- **CLI.** `localmcp read|extract|links <url>` run the same tools through the same policy, for agents that have a shell and want zero tool schema in context. `--json` prints `structuredContent`.
- **Signed in, but scoped.** `policy.allowInteract` accepts `"auto"` (now the default): `interact` is off whenever a saved login profile or an attached browser is in use, and on for throwaway sessions. `true` / `false` still force it.
- **Deny rules on every request.** `policy.deny` now aborts subresources, iframes and fetches to denied hosts, not just navigations, and holds in persistent-profile and CDP modes.
- **Cloaking guard.** Publisher markdown is used only if it matches the rendered page's title; otherwise the rendered page is used and the result says so.
- **Reproducible benchmark.** `npm run bench` writes `benchmarks/results.md`, comparing rendered HTML, a Playwright MCP snapshot and `browse` on named public pages.

### Changed
- Heading self-links (`## [Syntax](#syntax)`, `## Title[](#id)`) are stripped, so `focus` ranks on heading text and omitted-section lists read cleanly.
- `focus` no longer treats a page that opens straight into a `##` section as having a lead to keep.
- jsdom's CSS-parse errors no longer spam stderr.

### Breaking
- Default `policy.allowInteract` changed from `true` to `"auto"`. Set `true` explicitly to let the agent click and type with your signed-in session.

## 0.2.1 — 2026-10-01

### Added
- **More browsers.** `browser.engine` can be `"chromium"` (default), `"firefox"`, or `"webkit"` (Safari's engine). `browser.channel` runs an installed Google Chrome or Microsoft Edge (`"chrome"`, `"msedge"`, beta/dev channels). `cdpEndpoint` attaches to any Chromium-based browser you already run (Chrome, Edge, Brave, Arc, Vivaldi, Opera).
- `localmcp login [url] --browser firefox|webkit|chromium`.
- Each engine keeps its own persistent profile (`~/.localmcp/profile`, `profile-firefox`, `profile-webkit`), so switching engines never mixes session stores.

- **Metadata-first reading.** `browse`, `extract` and `focus` use the publisher's own markdown when a page offers it: a same-origin `<link rel="alternate" type="text/markdown">`, or `Accept: text/markdown` content negotiation. Otherwise the rendered DOM is distilled as before. Configure with `distill.publisherMarkdown` (default `true`).
- **Page card.** Each result starts with one line of provenance (type, site, author, published/updated, canonical, content source) built from JSON-LD (including `@graph`), OpenGraph, `<meta>`, canonical links and markdown front matter. It's also returned as `structuredContent.card`, with `structuredContent.source`.
- **`links` reports `/llms.txt`** when a site publishes one, guarding against soft-404 HTML pages.

### Fixed
- In-page scripts failed with `__name is not defined` when the server ran through `tsx` (`npm run dev`), because esbuild's keepNames wraps helper functions. Every page script now runs through a wrapper that works with any compiler.

### Roadmap
- Attach to your running Firefox (WebDriver BiDi) and Safari (`safaridriver`).
- Optional browser-extension bridge, so the agent can read tabs in your everyday browser without remote-debugging flags.

## 0.2.0 — 2026-09-30

### Added
- **Authenticated sessions that work.** `localmcp login [url]` signs in on a persistent profile (`~/.localmcp/profile`), used automatically via `browser.profile: "auto"`. `browser.cdpEndpoint` attaches to your own running Chrome. Earlier versions always used a fresh, cookie-less context, so signed-in pages showed a login screen.
- **`browse` focus and budget.** `focus` ranks sections (BM25 with heading boost). `maxTokens` enforces a budget (default `distill.maxTokens`, which was previously ignored). Truncated results list the omitted section headings.
- **`browse({ diff: true })`** replaces the `watch` tool. `watch` remains as a hidden alias.
- **`links` tool.** Returns de-duplicated absolute links with `sameOrigin` / `match` filters.
- **`extract` returns real structure.** JSON-LD, meta/OpenGraph, tables as row objects, and headings in `structuredContent`. With `schema`, it fills the schema via **MCP sampling** when the client supports it.
- **`interact` actions.** `press`, `check`, `uncheck`, `hover`, `scroll`, `wait` (in addition to `click`, `fill`, `select`). `selector` is now optional where it makes sense.
- **`screenshot`** supports `format: "jpeg"`, `quality`, and `waitFor`.
- **MCP spec features.** Tool `title` + `annotations` (read-only vs destructive), `outputSchema` + `structuredContent`, `isError` results, server `instructions`, progress notifications, and diff snapshots exposed as resources.
- **Policy.** `policy.allow` / `policy.deny` host globs, `policy.allowInteract` (read-only mode), `policy.allowFileUrls`. URLs are checked before navigation and again after cross-origin redirects or actions.
- **Prompt-injection fence.** Page content is wrapped in `<untrusted-page-content>`, and early-close attempts are neutralised.
- `init` prints ready-to-paste setup for Claude Code, Claude Desktop, Cursor, VS Code and Codex CLI, and no longer overwrites an existing `.localmcp.json`.
- `--version`, `help`, and friendlier `usage` output.

### Changed
- Navigation waits for DOMContentLoaded plus a bounded network-settle (≤2.5s), so client-rendered apps are read after they render.
- `browse` no longer appends every link and button by default. Pass `elements: true`, which also caps the list at 80 visible elements.
- Interactive-element selectors are now verified unique (id → data-testid → name → aria-label → structural path). The previous `nth-of-type` selectors were computed across the whole document and were often wrong.
- Relative links and images resolve to absolute URLs.
- Headerless tables (infoboxes, layout tables) render as rows instead of raw HTML. Pages where Readability discards section headings fall back to structure-preserving extraction.
- `includeLinks` / `includeImages` are honoured (images are dropped by default).
- Tool errors set `isError: true`.
- Server version is read from `package.json` (previously hard-coded and out of sync).
- `LOCALMCP_NO_LIMIT=1` overrides the circuit breaker (`HEADLESSDEV_NO_LIMIT` still works).

### Fixed
- Line diff falls back to a set-based diff on very large pages instead of allocating an O(n·m) table.
- Usage query no longer interpolates values into SQL.
