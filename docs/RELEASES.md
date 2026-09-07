# Releases and Docker Hub

> **Canonical guide:** [PUBLISH.md](https://github.com/shellui/identity-service/blob/main/PUBLISH.md) at the repository root.

This document describes how to cut a release of `identity-service` and publish the container image to [Docker Hub](https://hub.docker.com/) as `shellui/identity-service`.

For day-to-day local runs, see the **Docker (local run)** section in the repository README.

## Image overview

| Item             | Value                                                     |
| ---------------- | --------------------------------------------------------- |
| Registry         | Docker Hub                                                |
| Repository       | `shellui/identity-service`                                |
| Recommended tags | `0.4.1`, `0.4`, `latest` (see [Tagging](#tagging))        |
| Listen port      | `8000`                                                    |
| Data volume      | `/app/data` (SQLite default path: `/app/data/db.sqlite3`) |

The image contains application code and collected static files only. Secrets and runtime configuration are supplied via environment variables at container start (see `.env.example` in the repository root).

## Pre-release checklist

Run the automated checklist (same script as PRs to `main`):

```bash
./tools/pre-release-check.sh
```

See [PUBLISH.md](https://github.com/shellui/identity-service/blob/main/PUBLISH.md) for options and the manual breakdown. Summary:

### 1. Version alignment

Ensure these match the release version (e.g. `0.4.1`):

- `version` in `pyproject.toml` (OpenAPI / API metadata via `config.settings.VERSION`)
- `CHANGELOG.md` entry with date
- CI + pre-release workflows green on the release commit
- Git tag `v0.4.1` (optional but recommended; not enforced by the script)

### 2. No secrets in the build context

Confirm locally:

```bash
# .env must not be tracked or copied into the image
test ! -f .env || grep -q '^\.env$' .gitignore
docker build -t shellui/identity-service:release-check .
docker run --rm --entrypoint sh shellui/identity-service:release-check \
  -c 'test ! -f /app/.env && echo "OK: .env not in image"'
```

`.dockerignore` excludes `.env`, `*.sqlite3`, `.git`, and local tooling artifacts. Only `.env.example` is included (placeholders only).

### 3. Runtime requirements documented

Operators must set at minimum:

- `SECRET_KEY` — required; app refuses to start without it (Django sessions/CSRF)
- `JWT_PRIVATE_KEY` — required when `DEBUG=false`; RS256 JWT signing (see [docs/jwks.md](jwks.md))
- `ALLOWED_HOSTS` — hostnames for production (comma-separated, no scheme)
- `CSRF_TRUSTED_ORIGINS` — full URLs with scheme when using browser-based flows behind HTTPS

Optional but typical for production:

- `CORS_ALLOW_ALL_ORIGINS` — default `true` (permissive API CORS). Set `false` + `CORS_ALLOWED_ORIGINS` only for lock-down installs
- `POSTGRES_DATABASE_URL` — use Postgres instead of SQLite
- `SENTRY_DSN` — Sentry project DSN for error reporting (see README observability section)
- `SENTRY_ENVIRONMENT` — Sentry environment tag (e.g. `staging`, `production`)
- OAuth client id/secret per company (via Django admin or `/api/v1/admin/oauth-social-apps`)

### 4. Smoke test the image

```bash
export SECRET_KEY="$(uv run python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())")"
export JWT_PRIVATE_KEY="$(uv run python manage.py generate_jwt_keys 2>/dev/null | awk -F'\"' '/JWT_PRIVATE_KEY=/ {print $2}')"
# Or set JWT_PRIVATE_KEY from output of: uv run python manage.py generate_jwt_keys

docker build -t shellui/identity-service:0.4.1 .

docker run --rm -d --name identity-release-smoke -p 18000:8000 \
  -e SECRET_KEY \
  -e JWT_PRIVATE_KEY \
  -e ALLOWED_HOSTS=localhost,127.0.0.1 \
  shellui/identity-service:0.4.1

# Expect HTTP response (400 with company_id is fine — proves Gunicorn + Django are up)
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18000/api/v1/settings

# JWKS should return at least one RSA key
curl -s http://127.0.0.1:18000/.well-known/jwks.json | python -c "import sys,json; d=json.load(sys.stdin); assert len(d.get('keys',[]))>=1"

docker stop identity-release-smoke
```

### 5. Multi-architecture (recommended for Docker Hub)

If you build on Apple Silicon, the default image may be `linux/arm64` only. Most cloud VMs expect `linux/amd64`. Publish both with buildx:

```bash
docker buildx create --use --name multi 2>/dev/null || docker buildx use multi

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t shellui/identity-service:0.4.1 \
  --push .
```

For a quick single-platform push from your machine:

```bash
docker build -t shellui/identity-service:0.4.1 .
docker push shellui/identity-service:0.4.1
```

## Tagging

For semver release `0.4.1`, typical Docker Hub tags:

| Tag      | Purpose                                  |
| -------- | ---------------------------------------- |
| `0.4.1`  | Exact release (pin in production)        |
| `0.4`    | Latest patch in 0.4 line                 |
| `latest` | Newest published release (use with care) |

Example:

```bash
VERSION=0.4.1
IMAGE=shellui/identity-service

docker tag "${IMAGE}:${VERSION}" "${IMAGE}:0.4"
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"

docker push "${IMAGE}:${VERSION}"
docker push "${IMAGE}:0.4"
docker push "${IMAGE}:latest"
```

## Publish to Docker Hub

### Prerequisites

1. Docker Hub account with push access to the `shellui` organization (or your namespace).
2. Docker CLI logged in:

```bash
docker login
```

3. Clean git tree at the commit you intend to release (tag optional).

### Build and push (single platform)

From the repository root:

```bash
VERSION=0.4.1
IMAGE=shellui/identity-service

docker build -t "${IMAGE}:${VERSION}" .

docker push "${IMAGE}:${VERSION}"
```

### Build and push (amd64 + arm64)

```bash
VERSION=0.4.1
IMAGE=shellui/identity-service

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "${IMAGE}:${VERSION}" \
  -t "${IMAGE}:0.4" \
  -t "${IMAGE}:latest" \
  --push .
```

### Git tag (recommended)

```bash
git tag -a "v${VERSION}" -m "Release ${VERSION}"
git push origin "v${VERSION}"
```

There is no GitHub Actions workflow for Docker publish yet; releases are manual.

## Run the published image

Minimal example:

```bash
docker volume create identity-service-data

docker run -d \
  --name identity-service \
  -p 8000:8000 \
  -v identity-service-data:/app/data \
  -e SECRET_KEY='replace-with-generated-key' \
  -e JWT_PRIVATE_KEY='replace-with-pem-from-generate_jwt_keys' \
  -e ALLOWED_HOSTS='auth.example.com' \
  -e CSRF_TRUSTED_ORIGINS='https://auth.example.com,https://app.example.com' \
  shellui/identity-service:0.4.1
```

With Postgres:

```bash
-e POSTGRES_DATABASE_URL='postgres://user:pass@host:5432/dbname'
```

OAuth credentials are configured per company in the database (Django admin or `/api/v1/admin/oauth-social-apps`), not via container environment variables.

The entrypoint runs migrations on start, then starts Gunicorn as user `appuser`.

## Security notes

| Topic                     | Status                                                                                                                              |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `.env` in image           | Excluded via `.dockerignore` — verified absent in image                                                                             |
| Runtime `JWT_PRIVATE_KEY` | Must be provided in production; never baked into image                                                                              |
| JWKS endpoint             | `/.well-known/jwks.json` exposes public keys only                                                                                   |
| Build-time `SECRET_KEY`   | Used only for `collectstatic` during `docker build`; appears in build history as `build-only-not-for-runtime` — not used at runtime |
| `.env.example`            | Included; contains placeholder values only                                                                                          |
| SQLite / DB files         | Excluded from image; use volume or Postgres                                                                                         |
| Process user              | Gunicorn runs as `appuser`; entrypoint may run brief setup as root                                                                  |
| `DEBUG`                   | Defaults to `false` in Dockerfile and compose                                                                                       |

Do not commit `.env` or real OAuth secrets to git. Do not pass secrets as Docker build args unless you accept they may appear in image history.

## First release (0.1.0) — known limitations

Acceptable for an initial image; improve in later releases if needed:

- No `HEALTHCHECK` in the Dockerfile
- No automated Docker Hub publish in CI
- SQLite on a volume is fine for single-node trials; production should prefer `POSTGRES_DATABASE_URL`
- API version string in OpenAPI is `project.version` from `pyproject.toml` (exposed as `config.settings.VERSION`) — keep it in sync with the Docker tag
- Reverse proxy TLS termination: set `CSRF_TRUSTED_ORIGINS` and rely on `SECURE_PROXY_SSL_HEADER` when behind HTTPS

## Rollback

Pull and run a previous digest or tag:

```bash
docker pull shellui/identity-service:0.2.0
# or pin by digest from Docker Hub
```

Data in `identity-service-data` (or Postgres) is independent of the image tag; test migrations when downgrading.
