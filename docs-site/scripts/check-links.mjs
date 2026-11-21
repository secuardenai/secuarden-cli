// Check generated internal page/asset links. External links are not fetched.
import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
const root = resolve('dist');
const origin = 'https://cli-docs.secuarden.ai';
const base = '/';
async function* htmlFiles(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) yield* htmlFiles(path);
    else if (entry.name.endsWith('.html')) yield path;
  }
}
const failures = [];
let count = 0;
for await (const file of htmlFiles(root)) {
  count++;
  const route = base + relative(root, file).replaceAll('\\', '/').replace(/index\.html$/, '');
  const source = await readFile(file, 'utf8');
  for (const match of source.matchAll(/\b(?:href|src)=["']([^"']+)["']/g)) {
    const href = match[1].replaceAll('&amp;', '&');
    const url = new URL(href, origin + route);
    if (url.origin !== origin) continue;
    // Starlight's error document has a virtual /404/ canonical URL.
    if (file === resolve(root, '404.html') && url.pathname === base + '404/') continue;
    if (!url.pathname.startsWith(base)) {
      failures.push(`${relative(root, file)}: URL outside project base: ${href}`);
      continue;
    }
    const path = resolve(root, decodeURIComponent(url.pathname.slice(base.length)));
    if (relative(root, path).startsWith('..')) throw new Error('Link escapes build output');
    try {
      const info = await stat(path);
      if (info.isDirectory()) await stat(resolve(path, 'index.html'));
    } catch {
      failures.push(`${relative(root, file)}: ${href}`);
    }
  }
}
if (failures.length) throw new Error('Broken internal links:\n' + [...new Set(failures)].join('\n'));
console.log(`Checked internal links in ${count} generated HTML pages.`);
