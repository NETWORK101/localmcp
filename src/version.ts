import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

/** Read our own package.json version — works from src/ (tsx) and dist/src/ (built). */
function readVersion(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 4; i++) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8'));
      // The package is published as @localmcpserv/localmcp (0.3.0 manifests said
      // @network101/localmcp); the bare name is the
      // pre-scope manifest. Either is ours, so neither reports 0.0.0.
      if (pkg.name === 'localmcp' || pkg.name === '@network101/localmcp' || pkg.name === '@localmcpserv/localmcp') return pkg.version;
    } catch {
      /* keep walking up */
    }
    dir = dirname(dir);
  }
  return '0.0.0';
}

export const VERSION = readVersion();
