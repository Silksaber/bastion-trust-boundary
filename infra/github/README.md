# The GitHub App

The manifest in [`app-manifest.json`](app-manifest.json) is the literal document
GitHub is asked to create the App from. It is checked in for the same reason the
cloud role's policy is shown literally rather than described in prose: the permissions
we ask for are the whole basis on which a customer decides to trust us, and a document
they can read is worth more than an adjective.

Register one with:

```bash
python scripts/register_github_app.py
```

## Installation ownership and user authorization

An installation ID in a setup redirect is not proof that the connecting user can
access it. After setup, Bastion sends the same signed-in browser through GitHub App
user authorization, with single-use state and S256 PKCE. Only an installation returned
by the user-token installation inventory can be connected. The temporary user token
is not persisted; repository jobs continue to use encrypted installation tokens.

Existing deployments must set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` from their
GitHub App settings and register `{API_BASE_URL}/connections/github/authorize` as a
**Callback URL**. Keep the existing setup URL and leave `request_oauth_on_install`
disabled: the setup callback starts the separate authorization step. New registrations
include the callback and write both client credentials into the generated secret env
file. The client ID is different from `GITHUB_APP_ID`.

Without those settings, new connections are unavailable. Existing connections can
continue using their existing installation credentials. No additional repository
permission is requested by this authorization change.

See [GitHub's setup URL warning](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url).

## Permissions

| Permission | Level | Why it is needed |
|---|---|---|
| `metadata` | read | List the repositories an installation exposes, with their names, visibility, and default branches. |
| `contents` | write | Clone source and author branches containing accepted fixes. |
| `pull_requests` | write | Create releases, publish review comments and perform policy-authorized merges. |
| `checks` | write | Publish the PR gate's check runs. |

`scripts/check_github_permissions.py` checks this set against the manifest. The app
has no administration, workflows, actions or secrets permission.

## Events

| Event | Handled by |
|---|---|
| `installation` | Stage 2 — connect, uninstall, suspend, unsuspend |
| `installation_repositories` | Stage 2 — repository added to or removed from the installation |
| `push` | Stage 2 keeps repository metadata current. Stage 3 attaches scans here. |
| `pull_request` | Analyze the changed head and maintain PR/release lifecycle state. |

`installation` and `installation_repositories` are not listed in the manifest's
`default_events` — GitHub sends both to every App with installations regardless of
subscription, and its manifest validator rejects them if named explicitly ("default
events unsupported"). The webhook router still dispatches on both; only the manifest
omits them.

## URLs

`{API_BASE_URL}` is substituted from `API_BASE_URL` at registration time.

- **Webhook** — `POST {API_BASE_URL}/webhooks/github`, HMAC-verified with the
  generated secret.
- **Setup URL** — `{API_BASE_URL}/connections/github/callback`. Where GitHub returns
  the browser after an install, carrying the single-use handoff state.
- **User authorization callback** — `{API_BASE_URL}/connections/github/authorize`.
  Receives the authorization code after setup, before claiming the installation.
- **Redirect URL** is absent from the manifest on purpose. It is only used once, to
  return the *registration* code to `scripts/register_github_app.py`, so the script
  sets it to its own `localhost` listener rather than to anything this API serves.

Developing locally means GitHub cannot reach `localhost`. Point `API_BASE_URL` at a
tunnel (`cloudflared tunnel --url http://localhost:8000`, `ngrok http 8000`) and
register the App against that hostname.
