# Auth

Node.js app for user sign in via Google authentication.

## Env

| name                  | description                                        | required |
|-----------------------|----------------------------------------------------|----------|
| PORT                  | http server port                                   | true     |
| GOOGLE_CLIENT_ID      | OAuth client id                                    | true     |
| GOOGLE_CLIENT_SECRET  | OAuth client secret                                | true     |
| AUTH_DOMAIN           | Authentication host, e.g. https://auth.foo.com     | true     |
| SESSION_DOMAIN        | Domain to use for session cookie, e.g foo.com      | false    |
| SESSION_SECRET        | Session secret, used to store the user session     | true     |
| STORE_URL             | URL of store endpoint for [@cloud-cli/store](https://github.com/cloud-cli/store).        | true     |

Get the client ID and secret from [Google API console](https://console.cloud.google.com/apis/credentials)

- Authorized origin: `AUTH_DOMAIN`.
- Authorized redirect URI's: `AUTH_DOMAIN` + "/auth/google/callback".

Set SESSION_DOMAIN to the domain root in which authentication will be used. For example, "foo.com" will
set authentication for any *.foo.com domain, using a common cookie.

For `fetch` requests, add `{ credentials: 'include' }` to the request options to include the session.

## Usage

Just run the Docker image:

```bash
docker run --name 'auth' --detach \
  -e GOOGLE_CLIENT_ID='xxx' \
  -e GOOGLE_CLIENT_SECRET='xxx' \
  -e AUTH_DOMAIN='https://auth.foo.com/' \
  -e SESSION_DOMAIN='foo.com' \
  -e SESSION_SECRET='xxx' \
  -e STORE_URL='https://foo.xyz/123' \
  -e PORT=3000 \
  ghcr.io/cloud-cli/auth:latest
```

## RESTful API

*GET /:

Returns a JSON with `{ id, displayName, photo, properties }`

*DELETE /*:

Deletes the current session

*HEAD /*:

Returns 204 if authenticated, 401 if not

*GET /login?url=xxx*:

Browser login page. Optionally, redirects after login

*GET /me*:

Profile page of currently logged in user

*PUT /properties*:

Add a property to current user.
Request body is a JSON with `{ key, value }`

*DELETE /properties/:key*:

Delete user property

*GET /properties*:

Get all user properties

## Javascript API

Consider this app is running at `https://auth.foo.com`:

```js
import { getProfile, getProperties, getProperty, setProperty, deleteProperty } from 'https://auth.foo.com/index.mjs';

await setProperty('foo', 'yes');
const foo = await getProperty('foo'); // yes
await deleteProperty('foo');
console.log(await getProperties(), await getProfile());

```