// Ship the complete upstream notices alongside the minified production bundle.
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const groups = JSON.parse(execFileSync('pnpm', ['licenses', 'list', '--prod', '--json'], { encoding: 'utf8' }));
const packages = Object.values(groups).flat().sort((a, b) => a.name.localeCompare(b.name, 'en'));
const notices = ['NetGuard dashboard: third-party notices',
  'Includes the locked frontend production dependencies and their type declarations.',
  'Upstream copyright and license text is preserved below.\n'];
for (const pkg of packages) {
  const root = pkg.paths[0];
  const files = readdirSync(root).filter(name => /^licen[cs]e(?:[.-]|$)/i.test(name)).sort();
  if (files.length === 0) throw new Error(`Missing upstream license for ${pkg.name}`);
  notices.push(`=== ${pkg.name} ${pkg.versions.join(', ')} (${pkg.license}) ===`);
  if (pkg.homepage) notices.push(pkg.homepage);
  for (const file of files) notices.push(readFileSync(join(root, file), 'utf8').trim());
  notices.push('');
}
writeFileSync(new URL('../public/THIRD_PARTY_NOTICES.txt', import.meta.url), `${notices.join('\n').trimEnd()}\n`);
console.log(`Preserved upstream notices for ${packages.length} frontend packages`);
