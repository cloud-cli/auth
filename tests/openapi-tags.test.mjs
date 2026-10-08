import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const spec = JSON.parse(await readFile(new URL('../assets/openapi.json', import.meta.url), 'utf8'));
const operations = Object.entries(spec.paths).flatMap(([path, methods]) =>
  Object.entries(methods)
    .filter(([method]) => ['get', 'post', 'put', 'patch', 'delete', 'head'].includes(method))
    .map(([method, operation]) => ({ path, method, operation })),
);

test('OpenAPI splits authentication operations into readable sections', () => {
  const tags = spec.tags.map(({ name }) => name);
  for (const name of ['Profile', 'Properties', 'API tokens', 'JWT APIs', 'Admin-only APIs', 'UI-only APIs']) {
    assert.ok(tags.includes(name), `Missing OpenAPI tag: ${name}`);
  }
  assert.ok(operations.every(({ operation }) => !operation.tags?.includes('Authentication')));
  assert.equal(spec.paths['/api/v1/profile'].get.tags[0], 'Profile');
  assert.equal(spec.paths['/api/v1/properties'].get.tags[0], 'Properties');
  assert.equal(spec.paths['/api/v1/api-tokens/me'].get.tags[0], 'API tokens');
  assert.equal(spec.paths['/authorize'].get.tags[0], 'JWT APIs');
  assert.equal(spec.paths['/api/v1/oidc/clients'].get.tags[0], 'Admin-only APIs');
  assert.equal(spec.paths['/api/v1/webauthn/credentials'].get.tags[0], 'UI-only APIs');
});

test('every documented operation uses a declared section', () => {
  const tags = new Set(spec.tags.map(({ name }) => name));
  for (const { path, method, operation } of operations) {
    assert.ok(operation.tags?.length, `Missing tag for ${method.toUpperCase()} ${path}`);
    for (const name of operation.tags) assert.ok(tags.has(name), `Undeclared tag ${name}`);
  }
});

test('administrator user management operations are documented', () => {
  assert.equal(spec.paths['/api/v1/admin/users'].get.tags[0], 'Admin-only APIs');
  assert.equal(spec.paths['/api/v1/admin/users/{id}'].patch.tags[0], 'Admin-only APIs');
  assert.equal(spec.paths['/api/v1/admin/users/{id}'].delete.tags[0], 'Admin-only APIs');
  assert.ok(spec.paths['/api/v1/admin/users/{id}'].patch.requestBody);
});
