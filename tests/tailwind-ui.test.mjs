import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const uiDirectory = path.resolve('assets/ui');
const uiFiles = (await readdir(uiDirectory)).filter((name) => name.endsWith('.html'));
const uiSources = await Promise.all(uiFiles.map((name) => readFile(path.join(uiDirectory, name), 'utf8')));
const uiSource = uiSources.join('\n');
const tailwindConfig = await readFile('tailwind.config.css', 'utf8');
const builtCss = await readFile(path.join(uiDirectory, 'tailwind.generated.css'), 'utf8');

test('Tailwind is built locally with a shared CSS-first theme', async () => {
  assert.match(tailwindConfig, /@import ['"]tailwindcss['"] source\(none\)/);
  assert.match(tailwindConfig, /@theme\s*\{/);
  assert.match(tailwindConfig, /--color-brand:/);
  assert.match(tailwindConfig, /--spacing-property-field:/);
  assert.match(builtCss, /\.app-visibility-published/);
  assert.match(builtCss, /\.dark\\:bg-dark-surface/);
  assert.match(builtCss, /\.flex-0/);
  assert.match(builtCss, /\.justify-stretch/);
  assert.doesNotMatch(uiSource, /cdn\.tailwindcss\.com|tailwind\.config/);
  for (const page of [
    'landing.html',
    'login.html',
    'profile.html',
    'recovery.html',
    'passkey.html',
    'pwa.html',
    'qr-login.html',
    'v2.html',
  ]) {
    const source = await readFile(path.join(uiDirectory, page), 'utf8');
    assert.match(source, /href="\/ui\/tailwind\.generated\.css"/);
  }
});

test('UI templates avoid arbitrary utility classes and multi-token Li3 class bindings', () => {
  for (const source of uiSources) {
    for (const [, classValue] of source.matchAll(/\bclass="([^"]*)"/g)) {
      assert.doesNotMatch(classValue, /(?:^|\s)[\w:-]+-\[[^\s]*\]/);
    }
    for (const [, binding] of source.matchAll(/\bbind-class="([^"]*)"/g)) {
      for (const [, className] of binding.matchAll(/'([^']+)'\s*:/g)) {
        assert.doesNotMatch(className, /\s/, `Li3 bind-class must add one class token: ${className}`);
      }
    }
    for (const [, binding] of source.matchAll(/\battr-class="([^"]*)"/g)) {
      for (const [, className] of binding.matchAll(/'([^']+)'/g)) {
        assert.doesNotMatch(className, /\s/, `Li3 attr-class must set one class token: ${className}`);
      }
    }
  }
});
