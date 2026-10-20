import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import test from 'node:test';
import { iconData } from '../assets/ui/lucide-icons.mjs';

test('local Lucide data covers every icon used by the UI templates', async () => {
  const files = await readdir('assets/ui');
  const iconNames = new Set();

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
    assert.ok(iconData[name]?.length, `Missing local icon definition: ${name}`);
  }
});
