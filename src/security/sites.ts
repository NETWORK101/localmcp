import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

/**
 * Signed-in sites: the hosts a saved login profile is *for*.
 *
 * `localmcp login <url>` records the host it signed in to. The server then opens only those
 * hosts with the saved profile; every other URL gets a throwaway context with no cookies.
 * A page on some other site therefore can't load your Stripe dashboard with your session,
 * and reading a random page never happens "as you".
 *
 * The list lives inside the profile directory it describes, so each engine's profile
 * (profile, profile-firefox, profile-webkit) keeps its own.
 */
export interface SiteEntry {
  /** A hostname ("dashboard.stripe.com") or a subdomain glob ("*.stripe.com"). */
  host: string;
  addedAt: string;
  via: 'login' | 'manual';
}

interface SitesFile {
  version: 1;
  sites: SiteEntry[];
}

export const SITES_FILE = 'localmcp-sites.json';

export function sitesPath(profilePath: string): string {
  return join(profilePath, SITES_FILE);
}

export function loadSites(profilePath: string): SiteEntry[] {
  const p = sitesPath(profilePath);
  if (!existsSync(p)) return [];
  try {
    const parsed = JSON.parse(readFileSync(p, 'utf-8')) as Partial<SitesFile>;
    return Array.isArray(parsed.sites) ? parsed.sites.filter((s) => typeof s?.host === 'string') : [];
  } catch {
    return [];
  }
}

function save(profilePath: string, sites: SiteEntry[]): void {
  mkdirSync(profilePath, { recursive: true });
  const body: SitesFile = { version: 1, sites };
  writeFileSync(sitesPath(profilePath), JSON.stringify(body, null, 2) + '\n', { encoding: 'utf-8', mode: 0o600 });
}

/** Normalise user input ("https://dashboard.stripe.com/x", "Stripe.com", "*.stripe.com") to a host pattern. */
export function normaliseSite(input: string): string | null {
  const raw = input.trim().toLowerCase();
  if (!raw) return null;
  if (raw.startsWith('*.')) {
    const rest = normaliseSite(raw.slice(2));
    return rest && !rest.startsWith('*.') && !isPublicSuffixLike(rest) ? `*.${rest}` : null;
  }
  try {
    const url = new URL(raw.includes('://') ? raw : `https://${raw}`);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return url.hostname || null;
  } catch {
    return null;
  }
}

// Hosting platforms where every subdomain belongs to someone else.
const SHARED_SUFFIXES = new Set([
  'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app', 'web.app',
  'firebaseapp.com', 'herokuapp.com', 'appspot.com', 'blogspot.com', 'azurewebsites.net',
  'cloudfront.net', 'onrender.com', 'fly.dev', 'replit.app', 'ngrok.io', 'ngrok-free.app',
]);
const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'ne', 'or', 'go', 'gob', 'nic']);

/**
 * "*.com", "*.co.uk" or "*.github.io" would put most of the web in the signed-in profile.
 * A heuristic, not the Public Suffix List: it catches the forms people actually type.
 */
export function isPublicSuffixLike(host: string): boolean {
  const labels = host.split('.');
  if (labels.length < 2) return true;
  if (SHARED_SUFFIXES.has(host)) return true;
  return labels.length === 2 && labels[1].length === 2 && SECOND_LEVEL.has(labels[0]);
}

export function addSite(profilePath: string, input: string, via: SiteEntry['via'] = 'manual'): string | null {
  const host = normaliseSite(input);
  if (!host) return null;
  const sites = loadSites(profilePath);
  if (!sites.some((s) => s.host === host)) {
    sites.push({ host, addedAt: new Date().toISOString(), via });
    save(profilePath, sites);
  }
  return host;
}

export function removeSite(profilePath: string, input: string): boolean {
  const host = normaliseSite(input);
  const sites = loadSites(profilePath);
  const next = sites.filter((s) => s.host !== host);
  if (next.length === sites.length) return false;
  save(profilePath, next);
  return true;
}

/** "dashboard.stripe.com" matches itself; "*.stripe.com" matches any subdomain and the apex. */
export function siteMatches(pattern: string, hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (pattern.startsWith('*.')) {
    const apex = pattern.slice(2);
    return host === apex || host.endsWith(`.${apex}`);
  }
  return host === pattern;
}

export function isSignedInSite(url: string, sites: readonly SiteEntry[]): boolean {
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return false;
  }
  return sites.some((s) => siteMatches(s.host, host));
}
