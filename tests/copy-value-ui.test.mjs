import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

for (const path of ['assets/ui/copy-value.html', 'assets/ui/dashboard-copy-value.html']) {
  test(`${path} previews the key safely and copies on tap or click`, async () => {
    const source = await readFile(path, 'utf8');

    assert.match(source, /value\.length - 3/);
    assert.match(source, /tokenPrefix\.value = value\.slice\(0, splitAt\)/);
    assert.match(source, /tokenSuffix\.value = value\.slice\(splitAt\)/);
    assert.match(source, /<span class="min-w-0 flex-1 truncate">\{\{ tokenPrefix \}\}…<\/span>/);
    assert.match(source, /<span class="shrink-0">\{\{ tokenSuffix \}\}<\/span>/);
    assert.match(source, /aria-label="Copy full value to clipboard"/);
    assert.match(source, /on-click="copy\(\)"/);
    assert.match(source, /navigator\.clipboard\.writeText\(token\.value\)/);
    assert.doesNotMatch(source, /<input\b|selectText|select-all/);
  });
}
