# identity-service documentation

Welcome to the `identity-service` documentation.

This backend provides Shellui-compatible authentication endpoints under `/api/v1/*` using Django.

## Quick links

- Read project setup and usage in `README.md`.
- Explore the auth endpoints provided by the service.
- **[OAuth login](oauth-login.md)** — identity-hosted authorize/callback, provider registration, redirect allowlist, hosting sync.
- **[Company access modes](company-access.md)** — public, domain allow-list, invitation-only join rules.
- **[JWKS and JWT verification](jwks.md)** — RS256 signing, `/.well-known/jwks.json`, key rotation.
- **[Metrics (JWT & personal access tokens)](metrics.md)** — how to call `/api/v1/metrics` and `/api/v1/metrics/all`.
- **[Releases](RELEASES.md)** — Docker Hub image tags and publish checklist (see also root `PUBLISH.md`).
- Extend this docs folder with additional guides as the project evolves.
