// Check generated internal page/asset links. External links are not fetched.
import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
const root = resolve('dist');
const origin = 'https://cli-docs.secuarden.ai';
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
  const route = '/' + relative(root, file).replaceAll('\\', '/').replace(/index\.html$/, '');
  const source = await readFile(file, 'utf8');
  for (const match of source.matchAll(/\bhref=["']([^"']+)["']/g)) {
    const href = match[1].replaceAll('&amp;', '&');
    const url = new URL(href, origin + route);
    if (url.origin !== origin) continue;
    // Starlight's error document has a virtual /404/ canonical URL.
    if (file === resolve(root, '404.html') && url.pathname === '/404/') continue;
    const path = resolve(root, '.' + decodeURIComponent(url.pathname));
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
