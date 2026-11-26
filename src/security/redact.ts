/**
 * Keep credentials that appear on a page out of the model's context.
 *
 * Signed-in pages are exactly where keys show up: an API-keys screen, a webhook settings page,
 * a CI log. Once a key is in the context window it can be echoed, logged, or carried off by a
 * prompt injection. Each match is replaced with a labelled stub that keeps a short prefix, so
 * the agent can still say "there is a live Stripe secret key here" without holding it.
 */
interface Rule {
  label: string;
  re: RegExp;
  /** Characters of the match to keep, so the stub stays recognisable ("sk_live_"). */
  keep: number;
  check?: (match: string) => boolean;
}

const RULES: Rule[] = [
  { label: 'private-key', re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, keep: 0 },
  { label: 'stripe-key', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g, keep: 8 },
  { label: 'stripe-webhook-secret', re: /\bwhsec_[A-Za-z0-9]{20,}\b/g, keep: 6 },
  { label: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, keep: 7 },
  { label: 'openai-key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g, keep: 3 },
  { label: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/g, keep: 4 },
  { label: 'npm-token', re: /\bnpm_[A-Za-z0-9]{36}\b/g, keep: 4 },
  { label: 'slack-token', re: /\bxox[abeprs]-[A-Za-z0-9-]{10,}/g, keep: 5 },
  { label: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, keep: 4 },
  { label: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, keep: 4 },
  { label: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, keep: 0 },
  { label: 'card-number', re: /\b\d(?:[ -]?\d){12,18}\b/g, keep: 0, check: luhn },
];

export function luhn(candidate: string): boolean {
  const digits = candidate.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

export interface Redaction {
  text: string;
  /** Count per label, e.g. { "stripe-key": 2 }. */
  found: Record<string, number>;
}

export function redactSecrets(input: string): Redaction {
  const found: Record<string, number> = {};
  let text = input;
  for (const rule of RULES) {
    text = text.replace(rule.re, (m) => {
      if (rule.check && !rule.check(m)) return m;
      found[rule.label] = (found[rule.label] ?? 0) + 1;
      const tail = rule.label === 'card-number' ? `…${m.replace(/\D/g, '').slice(-4)}` : '';
      return `${m.slice(0, rule.keep)}[redacted ${rule.label}${tail}]`;
    });
  }
  return { text, found };
}

/** Redact every string inside a JSON-like value (structuredContent), in place-safe copy form. */
export function redactDeep<T>(value: T, found: Record<string, number>): T {
  if (typeof value === 'string') {
    const r = redactSecrets(value);
    for (const [k, n] of Object.entries(r.found)) found[k] = (found[k] ?? 0) + n;
    return r.text as T;
  }
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, found)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v, found);
    return out as T;
  }
  return value;
}

export function describeRedactions(found: Record<string, number>): string | null {
  const parts = Object.entries(found).map(([k, n]) => `${n} ${k}${n === 1 ? '' : 's'}`);
  if (parts.length === 0) return null;
  return `localmcp redacted ${parts.join(', ')} from this page (policy.redactSecrets). Ask the user if you need the value itself.`;
}
