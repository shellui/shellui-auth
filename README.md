# identity-service

`identity-service` is a Django backend that provides authentication endpoints compatible with Shellui (`backend.type = "shellui"`).

It supports OAuth login (GitHub/Google/Microsoft), issues JWT tokens, exposes Supabase-like auth routes under `/api/v1/*`, and returns user metadata that Shellui can use (including avatar URL).

## Features

- Shellui-compatible auth API at `/api/v1/*`
- OAuth login flow for GitHub, Google, Microsoft (identity-hosted callback — see [docs/oauth-login.md](docs/oauth-login.md))
- Company join modes: **public**, **domain** allow-list, or **invitation-only** (see [docs/company-access.md](docs/company-access.md))
- JWT access + refresh token issuance (RS256 with JWKS when `JWT_PRIVATE_KEY` is set)
- Token refresh endpoint (`grant_type=refresh_token`)
- User metadata endpoint (`/api/v1/user`)
- Permissive API CORS by default (`CORS_ALLOW_ALL_ORIGINS=true`) so hosted preview origins and custom shells can call JWT APIs without per-origin env edits; auth is Bearer JWT. OAuth token delivery stays strict via the company redirect allowlist (see [docs/oauth-login.md](docs/oauth-login.md))
- OpenAPI docs with drf-spectacular

## Project Structure

- `src/config/` Django project settings and URL routing
- `src/apps/authapi/` authentication API and OAuth flow
- `src/apps/companies/` example business domain app

## Main Auth Endpoints

- `GET /.well-known/jwks.json` public JWKS for RS256 JWT verification (see [docs/jwks.md](docs/jwks.md))
- `GET /api/v1/settings` list enabled login methods/providers
- `GET /api/v1/authorize?provider=github&redirect_to=...&company_id=...` start OAuth (provider `redirect_uri` is always this service’s `/api/v1/oauth/callback`; `redirect_to` is the SPA/CLI bounce target and must be allowlisted or loopback)
- `GET /api/v1/oauth/callback` provider callback (server-side code exchange + account confirmation + fragment redirect to `redirect_to`)
- `POST /api/v1/oauth/confirm` complete sign-in after the confirmation screen (browser form)
- `GET /api/v1/oauth/confirm?action=switch&confirm_token=…` restart OAuth with account picker (Google/Microsoft)
- `POST /api/v1/oauth/exchange` deprecated SPA code exchange (older shells that still receive `?code=` on the frontend)
- `GET/POST /api/v1/oauth-redirects` manage per-company post-OAuth bounce origins (staff or company owner); loopback always allowed; empty list denies non-loopback; `source=hosting` rows are synced from hosting-service
- `PUT/DELETE /api/v1/hosting-oauth-redirects` hosting-service sync using the caller's identity JWT (enabled company members)
- `POST /api/v1/token?grant_type=refresh_token` refresh session using `refresh_token` in the body (Bearer access token optional)
- `POST /api/v1/logout` logout endpoint
- `GET /api/v1/user` return authenticated user profile + metadata
- `PUT /api/v1/user` update user metadata

## Staff admin endpoints

These routes require a valid JWT whose user has `is_staff=true` (`user_metadata.is_staff` is set from Django when tokens are issued).

- `GET /api/v1/users?q=&page=&page_size=` — paginated user list (`page_size` capped at 100)
- `GET /api/v1/users/<id>` — single user (Django fields + `user_metadata` cache)
- `PUT /api/v1/users/<id>` — JSON body may include `first_name`, `last_name`, `is_staff` (staff only), `is_active` (staff or company owner; **per-company** membership enable), and optional `data` object to merge into cached metadata (same idea as `PUT /api/v1/user`). You cannot remove your own staff flag or disable your own company access via this API. Enabling a previously disabled membership emails the user.
- `PATCH /api/v1/companies/<id>/` — company owners may update `name`, `owner_ids`, `access_mode` (`public` \| `domain` \| `invite`), and `allowed_email_domains`.

## Quick Start

```bash
# Requires https://docs.astral.sh/uv/
uv sync
cp .env.example .env
# Set SECRET_KEY; generate JWT keys for production (DEBUG=false)
uv run python manage.py migrate
uv run python manage.py runserver
```

Dependencies live in `pyproject.toml` and are locked in `uv.lock`. Add a package with `uv add <name>`; refresh the lock with `uv lock`.

Configure OAuth credentials per company (Django admin → Company → OAuth clients, or `POST /api/v1/admin/oauth-social-apps`):

```bash
# After starting the service, create a company and add GitHub/Google/Microsoft client id + secret
# for that company via the admin API or Django admin UI.
```

## JWT private key (RS256)

Production (`DEBUG=false`) requires an RSA private key for JWT signing. Local dev can skip this when `DEBUG=true` (HS256 with `SECRET_KEY`).

Generate a key pair and print suggested env vars:

```bash
uv run python manage.py generate_jwt_keys
```

Copy the output into `.env` (or your secret manager). The private key must stay on one line with `\n` for newlines:

```bash
JWT_KEY_ID=abc123...
JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"
```

In Coolify / Docker secret UIs, paste **only the PEM** (quotes stripped). See [docs/jwks.md](docs/jwks.md).

`JWT_PUBLIC_KEY` is optional (derived from the private key). Verifiers fetch the public key from `GET /.well-known/jwks.json` — see [docs/jwks.md](docs/jwks.md).

With Docker Compose, add `JWT_PRIVATE_KEY` to `.env` before running when `DEBUG=false`.

## Shellui Frontend Config

In your Shellui config (`shellui.config.ts`):

```ts
backend: {
  type: "shellui",
  url: "http://localhost:8000",
  login: {
    methods: ["oauth"],
    oauthProviders: ["github"]
  }
}
```

## OAuth provider apps

Register a **single** Authorization callback URL on each provider (GitHub / Google / Microsoft) pointing at **identity-service** — not the shell. No query string:

| Environment | Callback URL |
|-------------|--------------|
| Local | `http://localhost:8000/api/v1/oauth/callback` |
| Production | `https://<identity-host>/api/v1/oauth/callback` |

Homepage / application URL may still be the shell (e.g. `http://localhost:4000`).

Also allowlist each shell **origin** for the company (e.g. `http://localhost:4000`, `https://app.example.com`) via Django admin → Company OAuth redirects, Shellui admin OAuth setup, or `POST /api/v1/oauth-redirects`. Loopback (`127.0.0.1` / `localhost`) is always allowed for `shellui login` / CLI.

Full flow, allowlist rules, hosting sync, and upgrade steps (including **0.4.1**): [docs/oauth-login.md](docs/oauth-login.md).

## Notes

- `/api/v1/settings` only enables providers configured for the requested company.
- Avatar URL from provider userinfo is included in JWT metadata (`user_metadata.avatar_url`) for Shellui profile display.

## Documentation (Docusaurus)

Project docs live in `docs/` and are built with Docusaurus config in `tools/docusaurus/`.

Generate docs:

```bash
./tools/generate-docs.sh
```

Output is generated in `tools/docusaurus/build`.

## Tests

```bash
uv run python manage.py test
```

Pull requests and pushes to `main` / `develop` run [`.github/workflows/ci.yml`](.github/workflows/ci.yml): Django tests, lockfile check, dependency audit (`pip-audit`), secret scan (gitleaks), markdown link check (lychee), and a Docker image build.

Pull requests **to `main`** also run the pre-release checklist ([`.github/workflows/pre-release.yml`](.github/workflows/pre-release.yml)) — same checks as:

```bash
./tools/pre-release-check.sh
```

## Releases (Docker Hub)

See [PUBLISH.md](PUBLISH.md) for the pre-release checklist (automated via `./tools/pre-release-check.sh`), tagging conventions, and steps to build, push, and deploy `shellui/identity-service` on Docker Hub.

## Docker (local run)

Build image:

```bash
docker build -t shellui/identity-service:local .
```

Run container:

```bash
docker volume create identity-service-data
docker run --rm -p 8000:8000 \
  -v identity-service-data:/app/data \
  --name identity-service \
  shellui/identity-service:local
```

API CORS allows all origins by default (Bearer JWT auth). For lock-down installs set `CORS_ALLOW_ALL_ORIGINS=false` and `CORS_ALLOWED_ORIGINS=…`.

The container runs migrations automatically, stores SQLite at `/app/data/db.sqlite3`, then starts with Gunicorn on `0.0.0.0:8000`. Production images run `collectstatic` at build time; [WhiteNoise](https://whitenoise.readthedocs.io/) serves `/admin/` and other collected static files from the app process (no separate static server required).

Runtime env vars:

- `SECRET_KEY` (required; Django sessions/CSRF — not used for JWT signing when `JWT_PRIVATE_KEY` is set)
- `JWT_PRIVATE_KEY` (required in production; RS256 private key PEM — generate with `uv run python manage.py generate_jwt_keys`, see [JWT private key](#jwt-private-key-rs256))
- `JWT_PUBLIC_KEY`, `JWT_KEY_ID`, `JWT_PREVIOUS_PUBLIC_KEY`, `JWT_PREVIOUS_KEY_ID` (optional; see JWKS docs)
- `JWT_ACCEPT_HS256_LEGACY` (default `true`; set `false` after RS256 migration)
- `JWT_ACCESS_TOKEN_LIFETIME` (default `5m`; e.g. `30s`, `5m`, `2h` — bare integer = seconds)
- `JWT_REFRESH_TOKEN_LIFETIME` (default `7d`)
- `DEBUG` (default `false`)
- `ALLOWED_HOSTS` (comma-separated hostnames; empty → `localhost,127.0.0.1`)
- `CSRF_TRUSTED_ORIGINS` (comma-separated full URLs with scheme; empty → common local dev URLs including Shellui ports)
- `CORS_ALLOW_ALL_ORIGINS` (default `true`; set `false` for lock-down installs)
- `CORS_ALLOWED_ORIGINS` (used only when `CORS_ALLOW_ALL_ORIGINS=false`; Shellui / admin front-end origins)
- `CORS_ALLOWED_ORIGIN_REGEXES` (optional; used only when `CORS_ALLOW_ALL_ORIGINS=false`)
- `POSTGRES_DATABASE_URL` (optional; when set, Postgres is used instead of SQLite)
- `GUNICORN_WORKERS` (default `2`)
- `GUNICORN_THREADS` (default `2`)
- `GUNICORN_TIMEOUT` (default `60`)
- `SENTRY_DSN` (optional; enable Sentry error reporting — leave empty in local dev)
- `SENTRY_ENVIRONMENT` (optional; default `development` when `DEBUG=true`, else `production`)
- `SENTRY_RELEASE` (optional; default `project.version` from `pyproject.toml`)
- `SENTRY_TRACES_SAMPLE_RATE` (optional; default `0` — errors only; set e.g. `0.1` for performance traces)

## Observability (Sentry)

To capture unhandled exceptions and `ERROR`-level Django logs in [Sentry](https://sentry.io), set `SENTRY_DSN` to your project DSN (from **Settings → Client Keys** in Sentry). Leave it empty for local development.

```bash
# .env
SENTRY_DSN=https://examplePublicKey@o0.ingest.sentry.io/0
SENTRY_ENVIRONMENT=development
```

Rebuild or restart after changing env vars. With Docker Compose, `SENTRY_DSN` is passed through from `.env` automatically.

## Docker Compose (recommended local run)

```bash
cp .env.example .env
docker compose up --build
```

Stop:

```bash
docker compose down
```

Data persists in named volume `identity-service-data` (`/app/data/db.sqlite3` in container).