# Auth

Node.js app to perform user authentication in multiple subdomains.

## Env

| name                  | description                                        | required |
|-----------------------|----------------------------------------------------|----------|
| PORT                  | http server port                                   | true     |
| GOOGLE_CLIENT_ID      | OAuth client id                                    | true     |
| GOOGLE_CLIENT_SECRET  | OAuth client secret                                | true     |
| AUTH_DOMAIN           | Authentication host, e.g. https://auth.foo.com     | true     |
| SESSION_DOMAIN        | Domain to use for session cookie, e.g foo.com      | true     |
| SESSION_SECRET        | Session secret, used to store the user session     | true     |

- Get the client ID and secret from [Google API console](https://console.cloud.google.com/apis/credentials)
- Set SESSION_DOMAIN to the domain root in which authentication will be used. For example, "foo.com" will
set authentication for any *.foo.com domain, using a common cookie.
- For `fetch` requests, add `{ credentials: 'include' }` to the request options to include the session.

## Usage

Just run the Docker image:

```bash
docker run --name 'auth' --detach \
  -e GOOGLE_CLIENT_ID='xxx' \
  -e GOOGLE_CLIENT_SECRET='xxx' \
  -e AUTH_DOMAIN='https://auth.foo.com/' \
  -e SESSION_DOMAIN='foo.com' \
  -e SESSION_SECRET='xxx' \
  -e PORT=3000 \
  ghcr.io/cloud-cli/auth:latest
```

## API

*GET /:

Returns a JSON with `{ id, displayName, photo, properties }`

*DELETE /*:

Deletes the current session

*HEAD /*:

Returns 204 if authenticated, 401 if not

*GET /login?url=xxx*:

Browser login page. Optionally, sets up a redirection after login

*GET /me*:

Current logged in profile
