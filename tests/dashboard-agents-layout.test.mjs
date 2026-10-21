import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const agents = await readFile(new URL('../assets/ui/dashboard-agents.html', import.meta.url), 'utf8');
const layout = await readFile(new URL('../assets/ui/dashboard-layout.html', import.meta.url), 'utf8');

test('Agent state badges and actions are controlled by template conditionals', () => {
  for (const condition of [
    'agent.self',
    'agent.disabled',
    'agent.canDisable',
    'token.revokedAt',
    '!token.revokedAt && !agent.disabled',
  ]) {
    assert.ok(agents.includes(`<template if="${condition}"`), `Missing template conditional: ${condition}`);
  }
  assert.doesNotMatch(agents, /<(?:span|button|p)\s+if=/);
});

test('Dashboard content remains scrollable within the mobile dynamic viewport', () => {
  assert.match(layout, /h-dvh min-h-0/);
  assert.match(layout, /min-h-0 flex-1 overscroll-contain overflow-y-auto touch-pan-y/);
});
