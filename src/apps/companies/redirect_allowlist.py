"""
OAuth login `redirect_to` allow list: only the auth server default callback or registered
prefix URLs for the company may receive tokens in the browser redirect flow.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from django.http import HttpRequest

from .models import Company, CompanyOAuthRedirect

DEFAULT_LOGIN_CALLBACK_PATH = '/login/callback'

SHELLUI_OAUTH_ERROR_PARAM = 'shellui_oauth_error'
SHELLUI_OAUTH_ERROR_CODE_PARAM = 'shellui_oauth_error_code'


def _lower_netloc(netloc: str) -> str:
    if not netloc or '@' in netloc:
        return netloc
    host, sep, port = netloc.partition(':')
    return f'{host.lower()}{sep}{port}'


def canonical_url_no_fragment(url: str) -> str:
    p = urlsplit((url or '').strip())
    scheme = (p.scheme or '').lower()
    netloc = _lower_netloc(p.netloc)
    path = p.path or ''
    query = p.query or ''
    return urlunsplit((scheme, netloc, path, query, ''))


def normalize_stored_base_url(url: str) -> str:
    """Normalize allow list entries for storage and comparison."""
    return canonical_url_no_fragment(url).rstrip('/')


def server_default_redirect_url(request: HttpRequest) -> str:
    return canonical_url_no_fragment(
        f'{request.scheme}://{request.get_host()}{DEFAULT_LOGIN_CALLBACK_PATH}',
    )


def normalize_client_redirect_url(request: HttpRequest, raw: str) -> tuple[str | None, str | None]:
    """
    Turn client `redirect_to` into an absolute URL without fragment.
    Returns (url, None) or (None, error_message).
    """
    s = (raw or '').strip()
    if not s:
        return None, 'Empty redirect_to.'
    if s.startswith('//'):
        return None, 'Invalid redirect_to.'
    if s.startswith('/'):
        if '\n' in s or '\r' in s or '\0' in s:
            return None, 'Invalid redirect_to.'
        joined = f'{request.scheme}://{request.get_host()}{s}'
        return canonical_url_no_fragment(joined), None
    p = urlsplit(s)
    if p.scheme not in ('http', 'https'):
        return None, 'redirect_to must use http or https.'
    if not p.netloc:
        return None, 'Invalid redirect_to.'
    return canonical_url_no_fragment(s), None


def url_prefix_allowed(allowed_prefix: str, candidate: str) -> bool:
    """True if candidate equals the prefix or is a longer path under that prefix (host-safe)."""
    a = normalize_stored_base_url(allowed_prefix)
    c = normalize_stored_base_url(candidate)
    if not a or not c:
        return False
    if c == a:
        return True
    if len(c) > len(a) and c[len(a)] == '/' and c.startswith(a):
        return True
    return False


def redirect_url_allowed_for_company(company: Company, absolute_url: str, request: HttpRequest) -> bool:
    candidate = canonical_url_no_fragment(absolute_url)
    if candidate == server_default_redirect_url(request):
        return True
    bases = CompanyOAuthRedirect.objects.filter(company=company, is_active=True).values_list(
        'base_url',
        flat=True,
    )
    for base in bases:
        if url_prefix_allowed(base, candidate):
            return True
    return False


def _hostname_is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    h = hostname.lower().strip('[]')
    return h in ('localhost', '127.0.0.1', '::1')


def loopback_client_bounce_url_for_oauth_error(
    request: HttpRequest,
    redirect_to_raw: str | None,
    error_message: str,
    *,
    error_code: str = 'oauth_authorize_failed',
) -> str | None:
    """
    When browser OAuth fails before leaving the auth host, send loopback dev clients back to their
    app with query params instead of a JSON error page (so the Shell UI stays visible).
    """
    raw = (redirect_to_raw or '').strip()
    if not raw:
        return None
    url, err = normalize_client_redirect_url(request, raw)
    if err or not url:
        return None
    host = urlsplit(url).hostname
    if not _hostname_is_loopback(host):
        return None
    p = urlsplit(url)
    pairs = [
        (k, v)
        for k, v in parse_qsl(p.query, keep_blank_values=True)
        if not k.startswith('shellui_oauth_')
    ]
    safe_msg = (error_message or '').replace('\r', ' ').replace('\n', ' ').strip()[:500]
    pairs.append((SHELLUI_OAUTH_ERROR_PARAM, safe_msg if safe_msg else 'OAuth request failed.'))
    code = (error_code or '').strip()[:64] or 'oauth_authorize_failed'
    pairs.append((SHELLUI_OAUTH_ERROR_CODE_PARAM, code))
    new_query = urlencode(pairs)
    return urlunsplit((p.scheme, p.netloc, p.path or '', new_query, ''))


def validate_redirect_to_for_company(
    *,
    company: Company,
    request: HttpRequest,
    redirect_to_raw: str | None,
) -> tuple[str | None, str | None]:
    """
    Resolve optional client `redirect_to` and validate against the company allow list.
    Returns (absolute_url_without_fragment, error_message).
    """
    raw = (redirect_to_raw or '').strip()
    if not raw:
        return server_default_redirect_url(request), None
    url, err = normalize_client_redirect_url(request, raw)
    if err:
        return None, err
    if not redirect_url_allowed_for_company(company, url, request):
        return None, 'redirect_to is not allowed for this company.'
    return url, None
