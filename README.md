# shellui-auth

`shellui-auth` is a Django backend that provides authentication endpoints compatible with ShellUI (`backend.type = "shellui"`).

It supports OAuth login (GitHub/Google/Microsoft), issues JWT tokens, exposes Supabase-like auth routes under `/auth/v1/*`, and returns user metadata that ShellUI can use (including avatar URL).

## Features

- ShellUI-compatible auth API at `/auth/v1/*`
- OAuth login flow for GitHub, Google, Microsoft
- JWT access + refresh token issuance
- Token refresh endpoint (`grant_type=refresh_token`)
- User metadata endpoint (`/auth/v1/user`)
- CORS setup for local ShellUI frontend (`http://localhost:4000`)
- OpenAPI docs with drf-spectacular

## Project Structure

- `src/config/` Django project settings and URL routing
- `src/apps/authapi/` authentication API and OAuth flow
- `src/apps/companies/` example business domain app

## Main Auth Endpoints

- `GET /auth/v1/settings` list enabled login methods/providers
- `GET /auth/v1/authorize?provider=github&redirect_to=...` start OAuth redirect
- `GET /auth/v1/oauth/callback` OAuth callback from provider
- `POST /auth/v1/token?grant_type=refresh_token` refresh session using refresh token
- `POST /auth/v1/logout` logout endpoint
- `GET /auth/v1/user` return authenticated user profile + metadata
- `PUT /auth/v1/user` update user metadata

## Quick Start

1. Create and activate a Python virtual environment.
2. Install dependencies:

```bash
cd src
pip install -r requirements.txt
```

3. Configure OAuth credentials (env vars or allauth SocialApp in DB):

```bash
export GITHUB_CLIENT_ID="..."
export GITHUB_CLIENT_SECRET="..."
```

4. Run migrations and start server:

```bash
python manage.py migrate
python manage.py runserver
```

## ShellUI Frontend Config

In your ShellUI config (`shellui.config.ts`):

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

## OAuth App (GitHub) Values

- Homepage URL: `http://localhost:4000`
- Authorization callback URL: `http://localhost:8000/auth/v1/oauth/callback`

## Notes

- `/auth/v1/settings` only enables providers that are actually configured.
- Avatar URL from provider userinfo is included in JWT metadata (`user_metadata.avatar_url`) for ShellUI profile display.