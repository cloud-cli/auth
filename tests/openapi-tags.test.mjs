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
  for (const name of [
    'Profile',
    'Properties',
    'API tokens',
    'Applications',
    'Agents',
    'JWT APIs',
    'Admin-only APIs',
    'UI-only APIs',
  ]) {
    assert.ok(tags.includes(name), `Missing OpenAPI tag: ${name}`);
  }
  assert.ok(operations.every(({ operation }) => !operation.tags?.includes('Authentication')));
  assert.equal(spec.paths['/api/v1/profile'].get.tags[0], 'Profile');
  assert.equal(spec.paths['/api/v1/properties'].get.tags[0], 'Properties');
  assert.equal(spec.paths['/api/v1/api-tokens/me'].get.tags[0], 'API tokens');
  assert.equal(spec.paths['/authorize'].get.tags[0], 'JWT APIs');
  assert.equal(spec.paths['/api/v1/oidc/clients'].get.tags[0], 'Admin-only APIs');
  assert.equal(spec.paths['/api/v1/oidc/apps'].get.tags[0], 'Applications');
  assert.equal(spec.paths['/api/v1/agents'].post.tags[0], 'Agents');
  assert.deepEqual(spec.paths['/api/v1/api-tokens/me'].get.security, [{ apiKeyAuth: [] }]);
  assert.deepEqual(spec.paths['/api/v1/api-tokens/{clientId}/{tokenId}/scopes'].put.security, [{ apiKeyAuth: [] }]);
  assert.equal(spec.paths['/api/v1/webauthn/credentials'].get.tags[0], 'UI-only APIs');
  assert.equal(spec.paths['/index.mjs'].get.tags[0], 'Browser client');
  assert.equal(spec.paths['/oidc.mjs'].get.tags[0], 'Browser client');
  assert.equal(spec.paths['/node.mjs'].get.tags[0], 'Node client');
});

test('OIDC app creation uses a display name and generated client ID', () => {
  const schema = spec.paths['/api/v1/oidc/clients'].post.requestBody.content['application/json'].schema;
  assert.deepEqual(schema.required, ['name', 'redirectUris']);
  assert.ok(schema.properties.name);
  assert.equal('id' in schema.properties, false);
  assert.deepEqual(spec.components.schemas.User.properties.role.enum, ['agent', 'user', 'admin']);
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

test('OIDC scope documentation includes opt-in offline access', () => {
  const scope = spec.paths['/authorize'].get.parameters.find(({ name }) => name === 'scope');
  assert.match(scope.description, /offline_access/);
  assert.match(scope.description, /openid is required/);
});

test('Auth API tokens may append but cannot replace client scopes', () => {
  const operation = spec.paths['/api/v1/api-tokens/{clientId}/scopes'].post;
  assert.deepEqual(operation.security, [{ bearerAuth: [] }]);
  assert.match(operation.description, /without changing existing scopes/);
  assert.match(operation.description, /cannot remove or replace scopes/);
  const scopes = operation.requestBody.content['application/json'].schema.properties.scopes;
  assert.equal(scopes.minItems, 1);
  assert.equal(scopes.maxItems, 100);
});
