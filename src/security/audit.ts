import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'fs';
import { dirname } from 'path';

/**
 * One line per tool call, so "what did the agent open with my session?" has an answer.
 * Paths are kept but query strings and fragments are dropped: they are where tokens and
 * exfiltrated data would sit, and the log must not become a second copy of them.
 */
export interface AuditEntry {
  ts: string;
  tool: string;
  host: string | null;
  path: string | null;
  session: 'signed-in' | 'anonymous' | 'none';
  outcome: 'ok' | 'error' | 'blocked';
  reason?: string;
  tokens?: number;
  redactions?: number;
  ms?: number;
}

export function urlParts(raw: unknown): { host: string | null; path: string | null } {
  if (typeof raw !== 'string') return { host: null, path: null };
  try {
    const u = new URL(raw);
    return { host: u.host || null, path: u.pathname || null };
  } catch {
    return { host: null, path: null };
  }
}

export class AuditLog {
  constructor(private readonly path: string | null) {}

  write(entry: Omit<AuditEntry, 'ts'>): void {
    if (!this.path) return;
    try {
      const dir = dirname(this.path);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      appendFileSync(this.path, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n', {
        encoding: 'utf-8',
        mode: 0o600,
      });
    } catch {
      // Auditing must never break a tool call (read-only home, full disk).
    }
  }
}

export function readAudit(path: string, tail = 50): AuditEntry[] {
  if (!existsSync(path)) return [];
  const lines = readFileSync(path, 'utf-8').trim().split('\n').filter(Boolean);
  const out: AuditEntry[] = [];
  for (const line of lines.slice(-tail)) {
    try {
      out.push(JSON.parse(line) as AuditEntry);
    } catch {
      /* skip a torn line */
    }
  }
  return out;
}
