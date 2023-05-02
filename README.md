# Auth

Node.js app to perform user authentication

## Env

| name                  | description                                        | required |
|-----------------------|----------------------------------------------------|----------|
| PORT                  | http server port                                   | true     |
| GOOGLE_CLIENT_ID      | OAuth client id                                    | true     |
| GOOGLE_CLIENT_SECRET  | OAuth client secret                                | true     |
| AUTH_CALLBACK_HOST    | Callback authentication host, e.g. https://foo.com | true     |

## Usage

Just run the Docker image:

```bash
docker run --name 'auth' --detach \
  -e GOOGLE_CLIENT_ID='xxx' \
  -e GOOGLE_CLIENT_SECRET='xxx' \
  -e AUTH_CALLBACK_HOST='https://foo.com/' \
  -e PORT=3000 ghcr.io/cloud-cli/auth:latest
```

## API

*GET /profile*:

Returns `{ id, displayName, photo? }`

*DELETE /*:

Delets the session and logs out

*GET /* or *HEAD /*:

Returns 200 if authenticated, 401 if not

*GET /login?url=xxx*:

Returns a login page. Optionally, sets up a redirection after login

*GET /success*:

Returns a confirmation page after login.