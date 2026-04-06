"""
Login audit helpers: privacy-oriented fields (hashed IP, truncated UA) and event recording.

Timezone: the server does not know the user's IANA timezone unless the client sends it
(`client_timezone` query param on /authorize, or JSON on social login). Browser JS can use
`Intl.DateTimeFormat().resolvedOptions().timeZone` and pass that value — it is a coarse hint,
not precise geolocation, and is optional.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import TYPE_CHECKING

from django.conf import settings

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.http import HttpRequest

from .models import LoginEvent

_IP_HASH_SALT = 'login_audit.ip'
_DEVICE_HASH_SALT = 'login_audit.device'


def get_client_ip(request: HttpRequest) -> str | None:
    """Best-effort client IP; prefers X-Forwarded-For first hop when present."""
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if isinstance(xff, str) and xff.strip():
        return xff.split(',')[0].strip()
    addr = request.META.get('REMOTE_ADDR')
    if isinstance(addr, str) and addr.strip():
        return addr.strip()
    return None


def hash_ip(ip: str | None) -> str | None:
    """One-way hash of IP for correlation without storing raw addresses (GDPR-friendly)."""
    if not ip or not str(ip).strip():
        return None
    digest = hashlib.sha256(
        f'{_IP_HASH_SALT}:{settings.SECRET_KEY}:{ip.strip()}'.encode('utf-8')
    ).hexdigest()
    return digest


def hash_client_device_id(device_id: str | None) -> str | None:
    """Hash optional first-party device id from client storage (never store raw)."""
    if not device_id or not str(device_id).strip():
        return None
    raw = str(device_id).strip()
    if len(raw) > 128:
        return None
    return hashlib.sha256(
        f'{_DEVICE_HASH_SALT}:{settings.SECRET_KEY}:{raw}'.encode('utf-8')
    ).hexdigest()


_IANA_TZ_RE = re.compile(r'^[A-Za-z0-9_+/\-]{1,64}$')


def normalize_client_timezone(value: str | None) -> str:
    """Validate IANA-like timezone strings from the client; return '' if invalid."""
    if not value or not isinstance(value, str):
        return ''
    s = value.strip()
    if not s or len(s) > 64:
        return ''
    if not _IANA_TZ_RE.match(s):
        return ''
    return s


def truncate_user_agent(ua: str | None, max_length: int = 512) -> str:
    if not ua or not isinstance(ua, str):
        return ''
    return ua.strip()[:max_length]


def sanitize_failure_reason(message: str | None, max_length: int = 255) -> str:
    if not message:
        return ''
    s = str(message).replace('\n', ' ').replace('\r', '').strip()
    return s[:max_length]


def _sanitize_geo_field(value: str | None, max_length: int) -> str:
    if not value or not isinstance(value, str):
        return ''
    return value.strip()[:max_length]


def resolve_client_geo(request: HttpRequest) -> tuple[str, str]:
    """
    Best-effort (country, city) from GeoIP using the client IP.

    Uses ``settings.SHELLUI_GEOIP_DATABASE_PATH`` to a MaxMind GeoLite2/GeoIP2 City ``.mmdb``
    file and the optional ``geoip2`` package. Returns ('', '') when the path is unset, the file
    is missing, the library is not installed, or lookup fails (e.g. private IP).
    """
    db_path = getattr(settings, 'SHELLUI_GEOIP_DATABASE_PATH', '') or ''
    if not db_path or not Path(db_path).is_file():
        return '', ''

    ip = get_client_ip(request)
    if not ip:
        return '', ''

    try:
        import geoip2.database
        from geoip2.errors import AddressNotFoundError, GeoIP2Error
    except ImportError:
        return '', ''

    try:
        with geoip2.database.Reader(db_path) as reader:
            rec = reader.city(ip)
    except (OSError, ValueError, AddressNotFoundError, GeoIP2Error):
        return '', ''

    country = rec.country.iso_code or rec.country.name or ''
    city = rec.city.name or ''
    return _sanitize_geo_field(country, 64), _sanitize_geo_field(city, 128)


def record_login_event(
    *,
    request: HttpRequest,
    outcome: str,
    provider: str,
    user: AbstractBaseUser | None = None,
    failure_reason: str | None = None,
    client_timezone: str = '',
    client_device_id: str | None = None,
    client_country: str | None = None,
    client_city: str | None = None,
) -> LoginEvent:
    ip = get_client_ip(request)
    ua = truncate_user_agent(request.META.get('HTTP_USER_AGENT'))
    tz = normalize_client_timezone(client_timezone) or normalize_client_timezone(
        request.META.get('HTTP_X_CLIENT_TIMEZONE') or request.META.get('HTTP_X_SHELLUI_CLIENT_TIMEZONE')
    )
    device_hash = hash_client_device_id(client_device_id)
    is_staff = bool(getattr(user, 'is_staff', False)) if user is not None else False

    geo_country, geo_city = resolve_client_geo(request)
    country = _sanitize_geo_field(
        geo_country if client_country is None else client_country,
        64,
    )
    city = _sanitize_geo_field(geo_city if client_city is None else client_city, 128)

    return LoginEvent.objects.create(
        user=user if user is not None else None,
        outcome=outcome,
        provider=str(provider).lower()[:32] if provider else 'unknown',
        failure_reason=sanitize_failure_reason(failure_reason),
        is_staff_at_event=is_staff,
        ip_hash=hash_ip(ip),
        user_agent=ua,
        client_timezone=tz,
        client_device_id_hash=device_hash or '',
        client_country=country,
        client_city=city,
    )


def oauth_callback_query_string(
    *,
    provider: str,
    redirect_to: str,
    client_timezone: str | None = None,
    client_device_id: str | None = None,
) -> str:
    """Build query string for OAuth redirect_uri (must match between authorize and token exchange)."""
    from urllib.parse import urlencode

    params: dict[str, str] = {
        'provider': provider,
        'redirect_to': redirect_to,
    }
    tz = normalize_client_timezone(client_timezone)
    if tz:
        params['client_timezone'] = tz
    if client_device_id and str(client_device_id).strip():
        d = str(client_device_id).strip()
        if len(d) <= 128:
            params['client_device_id'] = d
    return urlencode(params)


def oauth_callback_url(request: HttpRequest, provider: str, redirect_to: str) -> str:
    """Full redirect_uri for OAuth (authorize + callback token exchange)."""
    tz = request.GET.get('client_timezone', '') if hasattr(request, 'GET') else ''
    dev = request.GET.get('client_device_id', '') if hasattr(request, 'GET') else ''
    qs = oauth_callback_query_string(
        provider=provider,
        redirect_to=redirect_to,
        client_timezone=tz or None,
        client_device_id=dev or None,
    )
    return f"{request.scheme}://{request.get_host()}/auth/v1/oauth/callback?{qs}"
