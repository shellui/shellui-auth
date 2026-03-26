import json
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass

from django.conf import settings
from django.db.utils import OperationalError, ProgrammingError
from allauth.socialaccount.models import SocialApp


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scope: str


def _credentials_from_settings(provider: str) -> tuple[str, str]:
    provider_cfg = (getattr(settings, 'SOCIALACCOUNT_PROVIDERS', {}) or {}).get(provider, {})
    apps_cfg = provider_cfg.get('APPS', []) if isinstance(provider_cfg, dict) else []
    for app in apps_cfg:
        if not isinstance(app, dict):
            continue
        client_id = str(app.get('client_id', '')).strip()
        client_secret = str(app.get('secret', '')).strip()
        if client_id and client_secret:
            return client_id, client_secret

    env_client_id = str(getattr(settings, f'{provider.upper()}_CLIENT_ID', '') or '').strip()
    env_client_secret = str(getattr(settings, f'{provider.upper()}_CLIENT_SECRET', '') or '').strip()
    return env_client_id, env_client_secret


def _credentials_from_socialapp(provider: str) -> tuple[str, str]:
    try:
        app = SocialApp.objects.filter(provider=provider).exclude(client_id='').exclude(secret='').first()
    except (OperationalError, ProgrammingError):
        return '', ''
    if not app:
        return '', ''
    return str(app.client_id).strip(), str(app.secret).strip()


def get_provider_config(provider: str) -> ProviderConfig:
    tenant = settings.SOCIALACCOUNT_PROVIDERS.get('microsoft', {}).get('TENANT', 'common')
    client_id, client_secret = _credentials_from_settings(provider)
    if not client_id or not client_secret:
        db_client_id, db_client_secret = _credentials_from_socialapp(provider)
        client_id = client_id or db_client_id
        client_secret = client_secret or db_client_secret
    providers = {
        'github': ProviderConfig(
            name='github',
            client_id=client_id,
            client_secret=client_secret,
            authorize_url='https://github.com/login/oauth/authorize',
            token_url='https://github.com/login/oauth/access_token',
            userinfo_url='https://api.github.com/user',
            scope='read:user user:email',
        ),
        'google': ProviderConfig(
            name='google',
            client_id=client_id,
            client_secret=client_secret,
            authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
            token_url='https://oauth2.googleapis.com/token',
            userinfo_url='https://www.googleapis.com/oauth2/v3/userinfo',
            scope='openid email profile',
        ),
        'microsoft': ProviderConfig(
            name='microsoft',
            client_id=client_id,
            client_secret=client_secret,
            authorize_url=f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize',
            token_url=f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
            userinfo_url='https://graph.microsoft.com/v1.0/me',
            scope='openid email profile User.Read',
        ),
    }
    if provider not in providers:
        raise ValueError(f'Unsupported provider: {provider}')
    return providers[provider]


def build_authorize_url(provider: str, redirect_uri: str, state: str | None = None) -> str:
    config = get_provider_config(provider)
    params = {
        'client_id': config.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': config.scope,
        'state': state or str(uuid.uuid4()),
    }
    if provider == 'google':
        params['access_type'] = 'offline'
        params['prompt'] = 'consent'
    return f"{config.authorize_url}?{urllib.parse.urlencode(params)}"


def exchange_code_for_token(provider: str, code: str, redirect_uri: str) -> str:
    config = get_provider_config(provider)
    payload = {
        'client_id': config.client_id,
        'client_secret': config.client_secret,
        'code': code,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    }
    encoded = urllib.parse.urlencode(payload).encode('utf-8')
    req = urllib.request.Request(
        config.token_url,
        data=encoded,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        data = json.loads(response.read().decode('utf-8'))
    access_token = data.get('access_token')
    if not access_token:
        raise ValueError('No access token returned by provider.')
    return access_token


def fetch_provider_userinfo(provider: str, access_token: str) -> dict:
    config = get_provider_config(provider)
    req = urllib.request.Request(
        config.userinfo_url,
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        data = json.loads(response.read().decode('utf-8'))
    return data
