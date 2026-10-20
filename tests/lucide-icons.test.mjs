import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import test from 'node:test';

test('local Lucide SVG sprite covers every icon used by the UI templates', async () => {
  const files = await readdir('assets/ui');
  const iconNames = new Set();
  const sprite = await readFile('assets/ui/lucide-icons.svg', 'utf8');

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
    assert.ok(sprite.includes(`id="icon-${name}"`), `Missing local SVG sprite entry: ${name}`);
  }
});
