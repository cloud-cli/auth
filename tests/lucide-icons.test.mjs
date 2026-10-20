import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import test from 'node:test';

test('individual local Lucide SVGs cover every icon used by the UI templates', async () => {
  const files = await readdir('assets/ui');
  const iconNames = new Set();
  const iconDirectory = 'assets/ui/icons/v1.59.0';
  const iconFiles = new Set(await readdir(iconDirectory));
  const serverSource = await readFile('src/index.ts', 'utf8');
  const serverIconNames = serverSource.split('const lucideIconNames = [')[1]?.split('];')[0];
  assert.ok(serverIconNames, 'The server should explicitly allowlist local icon assets.');

  for (const file of files.filter((name) => name.endsWith('.html'))) {
    const source = await readFile(`assets/ui/${file}`, 'utf8');
    for (const [, value] of source.matchAll(/(?:attr-icon|icon)="([^"]+)"/g)) {
      const quotedNames = [...value.matchAll(/'([a-z][a-z0-9-]*)'/g)].map(([, name]) => name);
      if (quotedNames.length) {
        quotedNames.forEach((name) => iconNames.add(name));
      } else if (/^[a-z][a-z0-9-]*$/.test(value)) {
        iconNames.add(value);
      }
    }
  }

  for (const name of iconNames) {
    const file = `${name}.svg`;
    assert.ok(iconFiles.has(file), `Missing local SVG asset: ${name}`);
    const source = await readFile(`${iconDirectory}/${file}`, 'utf8');
    assert.ok(source.includes(`id="icon-${name}"`), `Local SVG has the wrong icon ID: ${name}`);
    assert.ok(serverIconNames.includes(`'${name}'`), `The server does not serve the local SVG asset: ${name}`);
  }
});
