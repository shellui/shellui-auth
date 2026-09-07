# Publish and deploy

How to build, publish, and run the `shellui/identity-service` Docker image on [Docker Hub](https://hub.docker.com/r/shellui/identity-service).

Publishing is **manual** — there is no CI workflow for Docker Hub yet.

## Image overview

| Item        | Value                                                |
| ----------- | ---------------------------------------------------- |
| Registry    | Docker Hub                                           |
| Repository  | `shellui/identity-service`                           |
| Listen port | `8000`                                               |
| Data volume | `/app/data` (SQLite default: `/app/data/db.sqlite3`) |

The image contains application code and collected static files only. Secrets and runtime configuration are supplied via environment variables at container start (see `.env.example`).

## Pre-release checklist

Complete these steps **before** building and pushing a release tag. Prefer the automated script (same checks run on PRs to `main`):

```bash
./tools/pre-release-check.sh
```

| Step              | What it verifies                                                                                                |
| ----------------- | --------------------------------------------------------------------------------------------------------------- |
| Version alignment | `pyproject.toml` version matches a dated `CHANGELOG.md` entry (`## [x.y.z] - YYYY-MM-DD`) and `uv.lock`         |
| Build secrets     | `.env` / `*.sqlite3` not tracked; `.gitignore` / `.dockerignore` exclude `.env`; built image has no `/app/.env` |
| Image smoke test  | Container serves `/api/v1/settings` and `/.well-known/jwks.json` with ≥1 RSA key                                |

Options: `--skip-docker` (version + git hygiene only), `--image TAG`, `--port PORT`.

GitHub Actions: [`.github/workflows/pre-release.yml`](.github/workflows/pre-release.yml) runs this script on every pull request targeting `main` (and via **workflow_dispatch**).

Manual equivalents (if you are not using the script):

### 1. Version alignment

Ensure these match the release version (e.g. `0.4.1`):

- `version` in `pyproject.toml` (OpenAPI / API metadata via `config.settings.VERSION`)
- `CHANGELOG.md` entry with date
- Git tag `v0.4.1` (optional but recommended; not enforced by the script)
- CI green on the release commit (`.github/workflows/ci.yml` + pre-release workflow)

### 2. No secrets in the build context

```bash
# .env must not be tracked or copied into the image
test ! -f .env || grep -qE '^\.env$' .gitignore

docker build -t shellui/identity-service:release-check .
docker run --rm --entrypoint sh shellui/identity-service:release-check \
  -c 'test ! -f /app/.env && echo "OK: .env not in image"'
```

`.dockerignore` excludes `.env`, `*.sqlite3`, `.git`, and local tooling artifacts. Only `.env.example` is included (placeholders only).

### 3. Smoke test the image

Covered by `./tools/pre-release-check.sh`. Manual form:

```bash
export SECRET_KEY="$(uv run python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())")"
eval "$(uv run python manage.py generate_jwt_keys --shell)"

VERSION=0.4.1
docker build -t "shellui/identity-service:${VERSION}" .

docker run --rm -d --name identity-release-smoke -p 18000:8000 \
  -e SECRET_KEY \
  -e JWT_PRIVATE_KEY \
  -e ALLOWED_HOSTS=localhost,127.0.0.1 \
  "shellui/identity-service:${VERSION}"

sleep 3
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18000/api/v1/settings
curl -s http://127.0.0.1:18000/.well-known/jwks.json | python -c "import sys,json; d=json.load(sys.stdin); assert len(d.get('keys',[]))>=1, d"
docker stop identity-release-smoke
```

## Publish to Docker Hub

### Prerequisites

1. Docker Hub account with push access to the `shellui` organization (or your namespace).
2. Docker CLI logged in:

```bash
docker login
```

3. Clean git tree at the commit you intend to release.

### Tagging

For semver release `0.4.1`, typical Docker Hub tags:

| Tag      | Purpose                                  |
| -------- | ---------------------------------------- |
| `0.4.1`  | Exact release (pin in production)        |
| `0.4`    | Latest patch in the 0.4 line             |
| `latest` | Newest published release (use with care) |

### Option A — single platform (fastest, not recommended, see option B)

From the repository root:

```bash
VERSION=0.4.1
IMAGE=shellui/identity-service

docker build -t "${IMAGE}:${VERSION}" .
docker push "${IMAGE}:${VERSION}"

# Optional extra tags
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:0.4"
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"
docker push "${IMAGE}:0.4"
docker push "${IMAGE}:latest"
```

### Option B — multi-arch (recommended for production)

If you build on Apple Silicon, a plain `docker build` may produce `linux/arm64` only. Most cloud VMs expect `linux/amd64`. Publish both with buildx:

```bash
VERSION=0.4.1
IMAGE=shellui/identity-service

docker buildx create --use --name multi 2>/dev/null || docker buildx use multi

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "${IMAGE}:${VERSION}" \
  -t "${IMAGE}:latest" \
  --push .
```

### Git tag (recommended)

```bash
VERSION=0.4.1
git tag -a "v${VERSION}" -m "Release ${VERSION}"
git push origin "v${VERSION}"
```

## Deploy

Pull and run the published image:

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

The entrypoint runs migrations on start, then starts Gunicorn as user `appuser`.

### Required runtime env vars (production)

| Variable               | Notes                                                                             |
| ---------------------- | --------------------------------------------------------------------------------- |
| `SECRET_KEY`           | Required; Django sessions/CSRF. Generate with `get_random_secret_key()`.          |
| `JWT_PRIVATE_KEY`      | Required when `DEBUG=false`; RS256 JWT signing. See [docs/jwks.md](docs/jwks.md). |
| `ALLOWED_HOSTS`        | Comma-separated hostnames, no scheme.                                             |
| `CSRF_TRUSTED_ORIGINS` | Full URLs with scheme when using browser flows behind HTTPS.                      |

### Optional runtime env vars

| Variable                     | Notes                                                                                          |
| ---------------------------- | ---------------------------------------------------------------------------------------------- |
| `CORS_ALLOW_ALL_ORIGINS`     | Default `true` (permissive API CORS; Bearer JWT is the auth boundary). Set `false` to lock down. |
| `CORS_ALLOWED_ORIGINS`       | Used when `CORS_ALLOW_ALL_ORIGINS=false`; Shellui / admin front-end origins.                   |
| `POSTGRES_DATABASE_URL`      | Use Postgres instead of SQLite.                                                                |
| `SENTRY_DSN`                 | Sentry error reporting.                                                                        |
| `SENTRY_ENVIRONMENT`         | e.g. `staging`, `production`.                                                                  |
| `JWT_ACCESS_TOKEN_LIFETIME`  | Default `5m`.                                                                                  |
| `JWT_REFRESH_TOKEN_LIFETIME` | Default `7d`.                                                                                  |

OAuth credentials are configured **per company** in the database (Django admin or `/api/v1/admin/oauth-social-apps`), not via container environment variables.

With Postgres:

```bash
-e POSTGRES_DATABASE_URL='postgres://user:pass@host:5432/dbname'
```

## Security notes

| Topic                     | Status                                                 |
| ------------------------- | ------------------------------------------------------ |
| `.env` in image           | Excluded via `.dockerignore`                           |
| Runtime `JWT_PRIVATE_KEY` | Must be provided in production; never baked into image |
| JWKS endpoint             | `/.well-known/jwks.json` exposes public keys only      |
| Build-time `SECRET_KEY`   | Used only for `collectstatic` during `docker build`    |
| SQLite / DB files         | Excluded from image; use volume or Postgres            |
| `DEBUG`                   | Defaults to `false` in Dockerfile                      |

Do not commit `.env` or real OAuth secrets to git. Do not pass secrets as Docker build args unless you accept they may appear in image history.

## Rollback

Pull and run a previous tag or digest:

```bash
docker pull shellui/identity-service:0.2.0
```

Data in `identity-service-data` (or Postgres) is independent of the image tag; test migrations when downgrading.
