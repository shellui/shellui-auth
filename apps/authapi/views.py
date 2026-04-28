import json
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlencode

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse, HttpResponseRedirect
from django.utils.dateparse import parse_datetime
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in
from django.contrib.sites.models import Site
from django.db import IntegrityError
from django.db.models import Count, Q
from django.db.utils import OperationalError, ProgrammingError
from allauth.socialaccount.models import SocialApp, SocialAccount
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from . import metrics as auth_metrics
from apps.companies.models import Company, CompanyGroup, CompanyOAuthClient
from apps.companies.redirect_allowlist import (
    loopback_client_bounce_url_for_oauth_error,
    validate_redirect_to_for_company,
)
from .renderers import DEFAULT_METRICS_RENDERERS
from .login_audit import oauth_callback_url, record_login_event
from .models import LoginEvent, UserPreference
from .user_activity import touch_user_last_seen
from .oauth import (
    build_authorize_url,
    exchange_code_for_token,
    fetch_provider_userinfo,
    get_provider_config,
)
from .serializers import (
    ProviderAuthorizeSerializer,
    ProviderCallbackSerializer,
    ShellUIOAuthExchangeSerializer,
    ShellUIAdminGroupCreateSerializer,
    ShellUIAdminGroupUpdateSerializer,
    ShellUIAdminOAuthClientCreateSerializer,
    ShellUIAdminOAuthSocialAppCreateSerializer,
    ShellUIAdminOAuthSocialAppUpdateSerializer,
    ShellUIAdminOAuthClientUpdateSerializer,
    ShellUIAdminUserUpdateSerializer,
    UserPreferenceSerializer,
)

User = get_user_model()

# Client-supplied user_metadata merges cannot set these; they are derived from Django / company state.
_SHELLUI_JWT_PRIVILEGED_METADATA_KEYS = frozenset({'is_staff', 'is_company_owner', 'groups'})


def _is_user_company_owner(user: User, company: Company) -> bool:
    return company.owners.filter(pk=user.pk).exists()


def _notify_user_logged_in_for_oauth(request, user: User) -> None:
    """
    OAuth success paths do not call django.contrib.auth.login(), so Django never emits
    user_logged_in and last_login stays stale. Fire the same signal so built-in
    update_last_login runs (and any other user_logged_in receivers).
    """
    user_logged_in.send(sender=user.__class__, request=request, user=user)
    touch_user_last_seen(user)


def _last_seen_at_for_user(user: User) -> str | None:
    """ISO 8601 timestamp from UserActivity, or None if never recorded."""
    try:
        ts = user.activity.last_seen_at
    except ObjectDoesNotExist:
        return None
    if ts is None:
        return None
    return ts.isoformat()


def _enrich_user_metadata_avatar(user: User, user_metadata: dict) -> None:
    """
    Fill user_metadata['avatar_url'] from cache, then linked SocialAccount extra_data (GitHub
    avatar_url, etc.). SPA OAuth (SocialLoginView) used to skip caching; this also fixes GET /user.
    """
    explicit = _normalize_avatar_url(user_metadata.get('avatar_url'))
    user_metadata['avatar_url'] = _resolve_avatar_url_for_jwt(user, explicit)


def _user_preferences_payload(user: User) -> dict:
    preference, _ = UserPreference.objects.get_or_create(user=user)
    return {
        'themeName': preference.theme_name,
        'language': preference.language,
        'region': preference.region,
        'colorScheme': preference.color_scheme,
    }


def _user_group_names(user: User, company: Company) -> list[str]:
    return list(
        CompanyGroup.objects.filter(company=company, members=user).values_list('name', flat=True).order_by('name')
    )


def _admin_user_group_rows(user: User, company: Company) -> list[dict]:
    return list(
        CompanyGroup.objects.filter(company=company, members=user).values('id', 'name').order_by('name')
    )


def _extract_user_data(provider: str, userinfo: dict, access_token: str) -> tuple[str, str, str, str | None]:
    provider_id = str(
        userinfo.get('id')
        or userinfo.get('sub')
        or userinfo.get('userPrincipalName')
        or userinfo.get('mail')
    )
    email = userinfo.get('email') or userinfo.get('mail') or userinfo.get('userPrincipalName')
    full_name = userinfo.get('name') or userinfo.get('displayName') or ''

    if provider == 'github' and not email:
        req = urllib.request.Request(
            'https://api.github.com/user/emails',
            headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
            },
        )
        with urllib.request.urlopen(req, timeout=20) as response:
            emails = json.loads(response.read().decode('utf-8'))
        primary = next((item for item in emails if item.get('primary')), None)
        if primary:
            email = primary.get('email')

    if not email:
        email = f'{provider_id}@{provider}.local'

    if not full_name:
        full_name = email.split('@')[0]

    avatar_url = userinfo.get('avatar_url') or userinfo.get('picture') or userinfo.get('photo')
    if not isinstance(avatar_url, str) or not avatar_url.strip():
        avatar_url = None

    return provider_id, email.lower(), full_name, avatar_url


def _normalize_avatar_url(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _resolve_avatar_url_for_jwt(user: User, explicit: str | None = None) -> str | None:
    """Resolve profile image URL for ShellUI JWT user_metadata (callback, refresh, rotation)."""
    url = _normalize_avatar_url(explicit)
    if url:
        return url
    cache_key = f"shellui:user_metadata:{user.id}"
    cached = cache.get(cache_key) or {}
    url = _normalize_avatar_url(cached.get('avatar_url') if isinstance(cached, dict) else None)
    if url:
        return url
    for account in SocialAccount.objects.filter(user=user):
        extra = account.extra_data or {}
        if not isinstance(extra, dict):
            continue
        url = _normalize_avatar_url(
            extra.get('avatar_url') or extra.get('picture') or extra.get('photo')
        )
        if url:
            return url
    return None


def _resolve_auth_provider_for_jwt(
    user: User,
    oauth_provider: str | None = None,
    prior_auth_provider: str | None = None,
) -> str:
    """OAuth callback provider wins; on refresh, keep prior JWT provider (e.g. github), not 'refresh'."""
    for candidate in (oauth_provider, prior_auth_provider):
        if isinstance(candidate, str) and candidate.strip():
            p = candidate.strip().lower()
            if p != 'refresh':
                return p
    account = SocialAccount.objects.filter(user=user).order_by('pk').first()
    if account and getattr(account, 'provider', None):
        return str(account.provider).lower()
    return 'refresh'


def _issue_tokens(user: User, company: Company) -> dict:
    user_payload = {
        'id': user.id,
        'email': user.email,
        'username': user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
    }
    refresh = RefreshToken.for_user(user)
    refresh['user'] = user_payload
    refresh['company_id'] = company.id
    access = refresh.access_token
    access['user'] = user_payload
    access['company_id'] = company.id
    return {
        'refresh': str(refresh),
        'access': str(access),
        'user': user_payload,
    }


def _parse_company_oauth_client_id(value: str | None) -> int | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _company_oauth_clients(company: Company) -> list[CompanyOAuthClient]:
    return list(
        CompanyOAuthClient.objects.filter(company=company, is_active=True)
        .exclude(social_app__client_id='')
        .exclude(social_app__secret='')
        .select_related('social_app')
        .order_by('social_app__provider', 'social_app__name', 'id')
    )


def _get_company_oauth_client(
    company: Company,
    provider: str,
    company_oauth_client_id: int | None,
) -> tuple[CompanyOAuthClient | None, str | None]:
    if company_oauth_client_id is None:
        return None, None
    row = (
        CompanyOAuthClient.objects.filter(
            pk=company_oauth_client_id,
            company=company,
            social_app__provider=provider,
            is_active=True,
        )
        .exclude(social_app__client_id='')
        .exclude(social_app__secret='')
        .select_related('social_app')
        .first()
    )
    if row:
        return row, None
    return None, 'Requested company_oauth_client_id is not available for this provider.'


def _enabled_oauth_providers(company: Company | None = None) -> list[str]:
    if company is not None:
        configured = sorted({str(row.social_app.provider).lower() for row in _company_oauth_clients(company)})
        return configured
    provider_ids = ('github', 'google', 'microsoft')
    configured = []
    social_provider_settings = getattr(settings, 'SOCIALACCOUNT_PROVIDERS', {}) or {}

    db_configured = set()
    try:
        db_apps = SocialApp.objects.filter(provider__in=provider_ids).values('provider', 'client_id', 'secret')
        db_configured = {
            str(app['provider']).lower()
            for app in db_apps
            if str(app.get('client_id', '')).strip() and str(app.get('secret', '')).strip()
        }
    except (OperationalError, ProgrammingError):
        db_configured = set()

    for provider in provider_ids:
        env_client_id = getattr(settings, f'{provider.upper()}_CLIENT_ID', '') or ''
        env_client_secret = getattr(settings, f'{provider.upper()}_CLIENT_SECRET', '') or ''
        env_ready = bool(str(env_client_id).strip() and str(env_client_secret).strip())

        provider_cfg = social_provider_settings.get(provider, {})
        apps_cfg = provider_cfg.get('APPS', []) if isinstance(provider_cfg, dict) else []
        settings_ready = any(
            isinstance(app, dict)
            and str(app.get('client_id', '')).strip()
            and str(app.get('secret', '')).strip()
            for app in apps_cfg
        )

        if env_ready or settings_ready or provider in db_configured:
            configured.append(provider)

    return configured


def _oauth_providers_from_settings() -> list[str]:
    cfg = getattr(settings, 'SOCIALACCOUNT_PROVIDERS', {}) or {}
    if not isinstance(cfg, dict):
        return []
    return sorted(str(k).strip().lower() for k in cfg.keys() if str(k).strip())


def _oauth_client_payload(row: CompanyOAuthClient) -> dict:
    social_app_settings = row.social_app.settings or {}
    if not isinstance(social_app_settings, dict):
        social_app_settings = {}
    return {
        'id': row.id,
        'provider': row.social_app.provider,
        'label': row.social_app.name,
        'client_id': row.social_app.client_id,
        'tenant': str(social_app_settings.get('tenant') or ''),
        'social_app_id': row.social_app_id,
        'is_active': row.is_active,
        'created_at': row.created_at,
        'updated_at': row.updated_at,
    }


def _oauth_social_app_payload(company: Company, app: SocialApp) -> dict:
    mapping = (
        CompanyOAuthClient.objects.filter(company=company, social_app=app)
        .order_by('-id')
        .first()
    )
    app_settings = app.settings if isinstance(app.settings, dict) else {}
    return {
        'id': app.id,
        'provider': app.provider,
        'name': app.name,
        'client_id': app.client_id,
        'tenant': str(app_settings.get('tenant') or ''),
        'is_linked': mapping is not None,
        'mapping_id': mapping.id if mapping is not None else None,
        'mapping_is_active': bool(mapping.is_active) if mapping is not None else False,
    }


def _generated_social_app_name(provider: str, company: Company) -> str:
    base = f'{provider}-company-{company.id}'
    candidate = base
    suffix = 2
    while SocialApp.objects.filter(name=candidate).exists():
        candidate = f'{base}-{suffix}'
        suffix += 1
    return candidate


def _issue_shellui_tokens(
    user: User,
    company: Company,
    avatar_url: str | None = None,
    *,
    oauth_provider: str | None = None,
    prior_app_metadata: dict | None = None,
) -> dict:
    refresh = RefreshToken.for_user(user)
    preferences = _user_preferences_payload(user)
    resolved_avatar = _resolve_avatar_url_for_jwt(user, avatar_url)
    user_metadata = {
        'name': user.get_full_name() or user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
        'avatar_url': resolved_avatar,
        'is_staff': bool(user.is_staff),
        'is_company_owner': _is_user_company_owner(user, company),
        'shelluiPreferences': preferences,
        'groups': _user_group_names(user, company),
    }
    app_meta_base = dict(prior_app_metadata) if isinstance(prior_app_metadata, dict) else {}
    prior_provider = app_meta_base.get('provider') if isinstance(app_meta_base.get('provider'), str) else None
    app_meta_base['provider'] = _resolve_auth_provider_for_jwt(
        user,
        oauth_provider=oauth_provider,
        prior_auth_provider=prior_provider,
    )
    app_metadata = app_meta_base
    access = refresh.access_token
    access['email'] = user.email
    access['company_id'] = company.id
    access['user_metadata'] = user_metadata
    access['app_metadata'] = app_metadata
    refresh['user_metadata'] = user_metadata
    refresh['company_id'] = company.id
    refresh['app_metadata'] = app_metadata
    now_ts = int(datetime.now(timezone.utc).timestamp())
    expires_at = int(access['exp'])
    return {
        'access_token': str(access),
        'refresh_token': str(refresh),
        'token_type': 'bearer',
        'expires_in': max(0, expires_at - now_ts),
        'expires_at': expires_at,
    }


def _link_social_account(user: User, provider: str, provider_id: str, userinfo: dict) -> None:
    # Persist provider payload in DB so one user can have multiple linked auth methods.
    SocialAccount.objects.update_or_create(
        provider=provider,
        uid=provider_id,
        defaults={
            'user': user,
            'extra_data': userinfo if isinstance(userinfo, dict) else {},
        },
    )


def _build_callback_redirect(redirect_to: str, payload: dict, provider: str) -> str:
    params = {
        'access_token': payload['access_token'],
        'refresh_token': payload['refresh_token'],
        'token_type': payload['token_type'],
        'expires_at': str(payload['expires_at']),
        'expires_in': str(payload['expires_in']),
        'provider': provider,
    }
    return f"{redirect_to}#{urlencode(params)}"


def _shellui_oauth_bounce_or_json(
    request,
    *,
    message: str,
    status_code: int = status.HTTP_400_BAD_REQUEST,
    error_code: str = 'oauth_authorize_failed',
    redirect_to_raw: str | None = None,
):
    """
    For loopback `redirect_to` targets, redirect back to the Shell app with `shellui_oauth_error`
    query params so the UI can render the message. Otherwise return JSON (e.g. production).
    """
    raw = redirect_to_raw if redirect_to_raw is not None else request.GET.get('redirect_to')
    bounce = loopback_client_bounce_url_for_oauth_error(
        request,
        raw,
        message,
        error_code=error_code,
    )
    if bounce:
        return HttpResponseRedirect(bounce)
    return Response({'error': message}, status=status_code)


def _authenticate_bearer_user(request):
    auth = JWTAuthentication()
    try:
        result = auth.authenticate(request)
    except (InvalidToken, TokenError):
        return None
    if not result:
        return None
    user, _ = result
    return user


def _required_company_from_request(request, user: User | None = None) -> tuple[Company | None, Response | None]:
    raw = (request.GET.get('company_id') or request.data.get('company_id') or '').strip()
    if not raw:
        return None, Response({'error': 'Missing company_id parameter.'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        company_id = int(raw)
    except (TypeError, ValueError):
        return None, Response({'error': 'Invalid company_id parameter.'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        company = Company.objects.get(pk=company_id)
    except Company.DoesNotExist:
        return None, Response({'error': 'Company not found.'}, status=status.HTTP_404_NOT_FOUND)

    if user is not None:
        if not company.members.filter(pk=user.pk).exists():
            return None, Response({'error': 'Forbidden for this company.'}, status=status.HTTP_403_FORBIDDEN)
        auth_token = getattr(request, 'auth', None)
        auth_company_id = auth_token.get('company_id') if auth_token is not None and hasattr(auth_token, 'get') else None
        if auth_company_id is not None and int(auth_company_id) != company.id:
            return None, Response(
                {'error': 'Requested company_id does not match token company_id.'},
                status=status.HTTP_403_FORBIDDEN,
            )
    return company, None


def _require_staff(request):
    user = _authenticate_bearer_user(request)
    if not user:
        return None, None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    if not user.is_staff:
        return None, None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
    company, cerr = _required_company_from_request(request, user=user)
    if cerr:
        return None, None, cerr
    return user, company, None


def _require_staff_or_company_owner(request):
    """
    Like `_require_staff` but also allows users in `company.owners` (same `company_id` as token).
    Used for company-scoped admin APIs so operators without Django `is_staff` can use the admin SPA.
    """
    user = _authenticate_bearer_user(request)
    if not user:
        return None, None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    company, cerr = _required_company_from_request(request, user=user)
    if cerr:
        return None, None, cerr
    if user.is_staff or _is_user_company_owner(user, company):
        return user, company, None
    return None, None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)


def _login_event_payload(event: LoginEvent) -> dict:
    return {
        'id': event.id,
        'company_id': event.company_id,
        'created_at': event.created_at,
        'user_id': event.user_id,
        'user_email': event.user.email if event.user_id else None,
        'outcome': event.outcome,
        'provider': event.provider,
        'failure_reason': event.failure_reason or '',
        'is_staff_at_event': event.is_staff_at_event,
        'ip_hash': event.ip_hash or '',
        'user_agent': event.user_agent or '',
        'client_timezone': event.client_timezone or '',
        'client_device_id_hash': event.client_device_id_hash or '',
        'client_country': event.client_country or '',
        'client_city': event.client_city or '',
    }


def _admin_user_payload(user: User, company: Company) -> dict:
    cache_key = f"shellui:user_metadata:{user.id}"
    user_metadata = cache.get(cache_key) or {
        'name': user.get_full_name() or user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
        'avatar_url': None,
        'is_staff': bool(user.is_staff),
    }
    user_metadata['is_staff'] = bool(user.is_staff)
    user_metadata['is_company_owner'] = _is_user_company_owner(user, company)
    user_metadata['shelluiPreferences'] = _user_preferences_payload(user)
    group_rows = _admin_user_group_rows(user, company)
    user_metadata['groups'] = [row['name'] for row in group_rows]
    user_metadata['last_seen_at'] = _last_seen_at_for_user(user)
    _enrich_user_metadata_avatar(user, user_metadata)
    return {
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'first_name': user.first_name or '',
        'last_name': user.last_name or '',
        'is_staff': user.is_staff,
        'is_company_owner': _is_user_company_owner(user, company),
        'is_active': user.is_active,
        'groups': group_rows,
        'user_metadata': user_metadata,
    }


@extend_schema_view(
    get=extend_schema(
        tags=['auth'],
        summary='Get social provider authorize URL',
        description='Generate an OAuth2 authorize URL for GitHub, Google, or Microsoft.',
        responses={200: OpenApiResponse(description='Authorization URL generated')},
    )
)
class SocialAuthorizeView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, provider: str):
        company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err
        company_oauth_client_id = _parse_company_oauth_client_id(request.GET.get('company_oauth_client_id'))
        _row, oauth_client_err = _get_company_oauth_client(company, provider, company_oauth_client_id)
        if oauth_client_err:
            return Response({'error': oauth_client_err}, status=status.HTTP_400_BAD_REQUEST)
        serializer = ProviderAuthorizeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        authorize_url = build_authorize_url(
            provider=provider,
            redirect_uri=serializer.validated_data['redirect_uri'],
            company_id=company.id,
            company_oauth_client_id=company_oauth_client_id,
        )
        return Response({'provider': provider, 'authorize_url': authorize_url})


@extend_schema_view(
    post=extend_schema(
        tags=['auth'],
        summary='Login with social provider',
        description='Exchange OAuth code and return JWT tokens plus user profile.',
        request=ProviderCallbackSerializer,
        responses={200: OpenApiResponse(description='Authenticated successfully')},
    )
)
class SocialLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, provider: str):
        company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err
        company_oauth_client_id = _parse_company_oauth_client_id(
            request.data.get('company_oauth_client_id') or request.GET.get('company_oauth_client_id')
        )
        _row, oauth_client_err = _get_company_oauth_client(company, provider, company_oauth_client_id)
        if oauth_client_err:
            return Response({'error': oauth_client_err}, status=status.HTTP_400_BAD_REQUEST)
        serializer = ProviderCallbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        client_tz = serializer.validated_data.get('client_timezone') or ''
        client_dev = serializer.validated_data.get('client_device_id') or None
        try:
            access_token = exchange_code_for_token(
                provider=provider,
                code=serializer.validated_data['code'],
                redirect_uri=serializer.validated_data['redirect_uri'],
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            userinfo = fetch_provider_userinfo(
                provider,
                access_token,
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            provider_id, email, full_name, avatar_url = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=None,
                company=company,
                failure_reason=str(exc),
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            return Response(
                {'detail': str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': f'{provider}_{provider_id}',
                'first_name': full_name.split(' ')[0],
                'last_name': ' '.join(full_name.split(' ')[1:]),
            },
        )
        if not created:
            if not user.first_name and full_name:
                user.first_name = full_name.split(' ')[0]
            if not user.last_name and ' ' in full_name:
                user.last_name = ' '.join(full_name.split(' ')[1:])
            user.save(update_fields=['first_name', 'last_name'])
        if not company.members.filter(pk=user.pk).exists():
            company.members.add(user)
        _link_social_account(user=user, provider=provider, provider_id=provider_id, userinfo=userinfo)

        cache.set(
            f"shellui:user_metadata:{user.id}",
            {
                'name': user.get_full_name() or user.get_username(),
                'full_name': user.get_full_name() or user.get_username(),
                'avatar_url': avatar_url,
            },
            timeout=60 * 60 * 24 * 30,
        )

        _notify_user_logged_in_for_oauth(request, user)
        auth_metrics.record_successful_login(provider, company_id=company.id)
        record_login_event(
            request=request,
            outcome=LoginEvent.OUTCOME_SUCCESS,
            provider=provider,
            user=user,
            company=company,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        token_payload = _issue_tokens(user, company=company)
        return Response(token_payload, status=status.HTTP_200_OK)


@extend_schema_view(
    get=extend_schema(
        tags=['auth'],
        summary='Get ShellUI auth capabilities',
        description=(
            'Return authentication capabilities for the ShellUI client, including enabled OAuth '
            'providers and feature flags used by the login UI.'
        ),
        responses={
            200: OpenApiResponse(
                description='Capabilities payload with methods, oauthProviders, and feature flags',
            ),
        },
    ),
)
class ShellUIAuthSettingsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err
        clients = _company_oauth_clients(company)
        providers = sorted({str(row.social_app.provider).lower() for row in clients})
        external = {provider: True for provider in providers}
        oauth_clients = [
            {
                'id': row.id,
                'provider': row.social_app.provider,
                'label': row.social_app.name,
            }
            for row in clients
        ]
        return Response(
            {
                'methods': ['oauth'] if providers else [],
                'oauthProviders': providers,
                'oauthClients': oauth_clients,
                'enable_oauth': bool(providers),
                'enable_magic_link': False,
                'external': external,
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['auth'],
        summary='Start OAuth authorization redirect',
        description=(
            'Validate the selected provider and redirect the browser to the provider authorization page. '
            'Use this endpoint for browser-based login.'
        ),
        parameters=[
            OpenApiParameter(
                name='provider',
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description='OAuth provider slug (github, google, or microsoft).',
            ),
            OpenApiParameter(
                name='redirect_to',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Frontend callback URL. Defaults to /login/callback on current host.',
            ),
            OpenApiParameter(
                name='client_timezone',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    'Optional IANA timezone from the browser (e.g. Europe/Paris), e.g. from '
                    'Intl.DateTimeFormat().resolvedOptions().timeZone. Stored as a coarse hint only.'
                ),
            ),
            OpenApiParameter(
                name='client_device_id',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    'Optional first-party device id (e.g. UUID in localStorage). Sent only as hashed value.'
                ),
            ),
        ],
        responses={
            302: OpenApiResponse(description='Redirect to provider authorize URL'),
            400: OpenApiResponse(description='Missing provider or provider not enabled'),
            500: OpenApiResponse(description='Provider is enabled but missing OAuth credentials'),
        },
    ),
)
class ShellUIAuthorizeView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        company, company_err = _required_company_from_request(request)
        if company_err:
            msg = 'Invalid request.'
            data = getattr(company_err, 'data', None)
            if isinstance(data, dict):
                msg = str(data.get('error') or msg)
            bounced = _shellui_oauth_bounce_or_json(
                request,
                message=msg,
                status_code=getattr(company_err, 'status_code', status.HTTP_400_BAD_REQUEST)
                or status.HTTP_400_BAD_REQUEST,
                error_code='authorize_company',
            )
            if isinstance(bounced, HttpResponseRedirect):
                return bounced
            return company_err
        provider = request.GET.get('provider', '').strip().lower()
        company_oauth_client_id = _parse_company_oauth_client_id(request.GET.get('company_oauth_client_id'))
        if not provider:
            return _shellui_oauth_bounce_or_json(
                request,
                message='Missing provider parameter.',
                error_code='missing_provider',
            )
        if provider not in _enabled_oauth_providers(company):
            return _shellui_oauth_bounce_or_json(
                request,
                message=f"Provider '{provider}' is not enabled.",
                error_code='provider_disabled',
            )
        _row, oauth_client_err = _get_company_oauth_client(company, provider, company_oauth_client_id)
        if oauth_client_err:
            return _shellui_oauth_bounce_or_json(
                request,
                message=oauth_client_err,
                error_code='oauth_client_unavailable',
            )
        cfg = get_provider_config(
            provider,
            company_id=company.id,
            company_oauth_client_id=company_oauth_client_id,
        )
        if not str(cfg.client_id).strip() or not str(cfg.client_secret).strip():
            return _shellui_oauth_bounce_or_json(
                request,
                message=(
                    f"Provider '{provider}' is missing OAuth credentials. "
                    f"Set {provider.upper()}_CLIENT_ID/{provider.upper()}_CLIENT_SECRET "
                    f"or configure an allauth SocialApp with client id + secret."
                ),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code='provider_oauth_misconfigured',
            )
        redirect_to, rerr = validate_redirect_to_for_company(
            company=company,
            request=request,
            redirect_to_raw=request.GET.get('redirect_to'),
        )
        if rerr or not redirect_to:
            err_code = (
                'redirect_not_allowed'
                if rerr and 'not allowed' in rerr
                else 'invalid_redirect'
            )
            return _shellui_oauth_bounce_or_json(
                request,
                message=rerr or 'Invalid redirect.',
                error_code=err_code,
            )
        authorize_url = build_authorize_url(
            provider=provider,
            redirect_uri=redirect_to,
            company_id=company.id,
            company_oauth_client_id=company_oauth_client_id,
        )
        return HttpResponseRedirect(authorize_url)


@extend_schema_view(
    get=extend_schema(
        tags=['auth'],
        summary='Handle OAuth callback and issue ShellUI tokens',
        description=(
            'Consume provider callback query params, exchange code for provider token, resolve user profile, '
            'and redirect to frontend callback with ShellUI access/refresh tokens in URL hash.'
        ),
        parameters=[
            OpenApiParameter(
                name='provider',
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description='OAuth provider slug used during authorize step.',
            ),
            OpenApiParameter(
                name='code',
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description='Authorization code returned by OAuth provider.',
            ),
            OpenApiParameter(
                name='redirect_to',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Frontend callback URL. Defaults to /login/callback on current host.',
            ),
            OpenApiParameter(
                name='client_timezone',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Optional IANA timezone echoed from the authorize step.',
            ),
            OpenApiParameter(
                name='client_device_id',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Optional device id echoed from the authorize step.',
            ),
        ],
        responses={
            302: OpenApiResponse(description='Redirect to frontend with auth payload in URL fragment'),
            400: OpenApiResponse(description='Missing/invalid callback parameters or provider exchange failure'),
        },
    ),
)
class ShellUIOAuthCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        company, company_err = _required_company_from_request(request)
        if company_err:
            msg = 'Invalid request.'
            data = getattr(company_err, 'data', None)
            if isinstance(data, dict):
                msg = str(data.get('error') or msg)
            bounced = _shellui_oauth_bounce_or_json(
                request,
                message=msg,
                status_code=getattr(company_err, 'status_code', status.HTTP_400_BAD_REQUEST)
                or status.HTTP_400_BAD_REQUEST,
                error_code='callback_company',
            )
            if isinstance(bounced, HttpResponseRedirect):
                return bounced
            return company_err
        provider = request.GET.get('provider', '').strip().lower()
        company_oauth_client_id = _parse_company_oauth_client_id(request.GET.get('company_oauth_client_id'))
        code = request.GET.get('code', '').strip()
        redirect_to, rerr = validate_redirect_to_for_company(
            company=company,
            request=request,
            redirect_to_raw=request.GET.get('redirect_to'),
        )
        if rerr or not redirect_to:
            err_code = (
                'redirect_not_allowed'
                if rerr and 'not allowed' in rerr
                else 'invalid_redirect'
            )
            return _shellui_oauth_bounce_or_json(
                request,
                message=rerr or 'Invalid redirect.',
                error_code=err_code,
            )
        if not provider or not code:
            return _shellui_oauth_bounce_or_json(
                request,
                message='Missing provider or code.',
                error_code='missing_provider_or_code',
            )
        _row, oauth_client_err = _get_company_oauth_client(company, provider, company_oauth_client_id)
        if oauth_client_err:
            return _shellui_oauth_bounce_or_json(
                request,
                message=oauth_client_err,
                error_code='oauth_client_unavailable',
            )
        callback_url = oauth_callback_url(request, provider, redirect_to)
        client_tz = request.GET.get('client_timezone', '')
        client_dev = request.GET.get('client_device_id', '') or None
        try:
            access_token = exchange_code_for_token(
                provider=provider,
                code=code,
                redirect_uri=callback_url,
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            userinfo = fetch_provider_userinfo(
                provider,
                access_token,
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            provider_id, email, full_name, avatar_url = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=None,
                company=company,
                failure_reason=str(exc),
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            bounced = _shellui_oauth_bounce_or_json(
                request,
                message=str(exc),
                error_code='token_exchange_failed',
            )
            if isinstance(bounced, HttpResponseRedirect):
                return bounced
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': f'{provider}_{provider_id}',
                'first_name': full_name.split(' ')[0],
                'last_name': ' '.join(full_name.split(' ')[1:]),
            },
        )
        if not created:
            if not user.first_name and full_name:
                user.first_name = full_name.split(' ')[0]
            if not user.last_name and ' ' in full_name:
                user.last_name = ' '.join(full_name.split(' ')[1:])
            user.save(update_fields=['first_name', 'last_name'])
        if not company.members.filter(pk=user.pk).exists():
            company.members.add(user)
        _link_social_account(user=user, provider=provider, provider_id=provider_id, userinfo=userinfo)

        cache.set(
            f"shellui:user_metadata:{user.id}",
            {
                'name': user.get_full_name() or user.get_username(),
                'full_name': user.get_full_name() or user.get_username(),
                'avatar_url': avatar_url,
            },
            timeout=60 * 60 * 24 * 30,
        )
        _notify_user_logged_in_for_oauth(request, user)
        payload = _issue_shellui_tokens(user, company=company, avatar_url=avatar_url, oauth_provider=provider)
        auth_metrics.record_successful_login(provider, company_id=company.id)
        record_login_event(
            request=request,
            outcome=LoginEvent.OUTCOME_SUCCESS,
            provider=provider,
            user=user,
            company=company,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        return HttpResponseRedirect(_build_callback_redirect(redirect_to, payload, provider=provider))


@extend_schema_view(
    post=extend_schema(
        tags=['auth'],
        summary='Exchange OAuth code for ShellUI tokens',
        description=(
            'Used by frontend OAuth callback routes. Exchanges provider authorization code, '
            'provisions/updates user mapping, and returns ShellUI tokens as JSON.'
        ),
        request=ShellUIOAuthExchangeSerializer,
        responses={
            200: OpenApiResponse(description='Token payload returned'),
            400: OpenApiResponse(description='Invalid payload or provider exchange failure'),
        },
    ),
)
class ShellUIOAuthExchangeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err
        serializer = ShellUIOAuthExchangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        provider = str(validated['provider']).strip().lower()
        code = str(validated['code']).strip()
        redirect_uri = validated['redirect_uri']
        company_oauth_client_id = validated.get('company_oauth_client_id')
        _row, oauth_client_err = _get_company_oauth_client(company, provider, company_oauth_client_id)
        if oauth_client_err:
            return Response({'error': oauth_client_err}, status=status.HTTP_400_BAD_REQUEST)
        client_tz = validated.get('client_timezone') or ''
        client_dev = validated.get('client_device_id') or None
        try:
            access_token = exchange_code_for_token(
                provider=provider,
                code=code,
                redirect_uri=redirect_uri,
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            userinfo = fetch_provider_userinfo(
                provider,
                access_token,
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            provider_id, email, full_name, avatar_url = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=None,
                company=company,
                failure_reason=str(exc),
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': f'{provider}_{provider_id}',
                'first_name': full_name.split(' ')[0],
                'last_name': ' '.join(full_name.split(' ')[1:]),
            },
        )
        if not created:
            if not user.first_name and full_name:
                user.first_name = full_name.split(' ')[0]
            if not user.last_name and ' ' in full_name:
                user.last_name = ' '.join(full_name.split(' ')[1:])
            user.save(update_fields=['first_name', 'last_name'])
        if not company.members.filter(pk=user.pk).exists():
            company.members.add(user)
        _link_social_account(user=user, provider=provider, provider_id=provider_id, userinfo=userinfo)

        cache.set(
            f"shellui:user_metadata:{user.id}",
            {
                'name': user.get_full_name() or user.get_username(),
                'full_name': user.get_full_name() or user.get_username(),
                'avatar_url': avatar_url,
            },
            timeout=60 * 60 * 24 * 30,
        )
        _notify_user_logged_in_for_oauth(request, user)
        payload = _issue_shellui_tokens(user, company=company, avatar_url=avatar_url, oauth_provider=provider)
        auth_metrics.record_successful_login(provider, company_id=company.id)
        record_login_event(
            request=request,
            outcome=LoginEvent.OUTCOME_SUCCESS,
            provider=provider,
            user=user,
            company=company,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        return Response(payload, status=status.HTTP_200_OK)


@extend_schema_view(
    post=extend_schema(
        tags=['auth'],
        summary='Refresh access token using refresh token',
        description=(
            'Issue a new ShellUI token pair from a valid refresh token. '
            'Requires grant_type=refresh_token in query params or JSON body.'
        ),
        parameters=[
            OpenApiParameter(
                name='grant_type',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Must be refresh_token.',
            ),
        ],
        responses={
            200: OpenApiResponse(description='New access_token and refresh_token payload'),
            400: OpenApiResponse(description='Unsupported grant_type or missing refresh_token'),
            401: OpenApiResponse(description='Invalid refresh token'),
        },
    ),
)
class ShellUITokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err
        grant_type = request.GET.get('grant_type') or request.data.get('grant_type')
        if grant_type != 'refresh_token':
            return Response(
                {'error': 'Only grant_type=refresh_token is supported.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        refresh_token = request.data.get('refresh_token')
        if not isinstance(refresh_token, str) or not refresh_token.strip():
            return Response({'error': 'Missing refresh_token.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            refresh = RefreshToken(refresh_token)
            user_id = refresh.get('user_id')
            user = User.objects.get(pk=user_id)
        except Exception:
            return Response({'error': 'Invalid refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)

        prior_meta = refresh.get('user_metadata')
        prior_avatar = None
        if isinstance(prior_meta, dict):
            prior_avatar = _normalize_avatar_url(prior_meta.get('avatar_url'))

        prior_app = refresh.get('app_metadata')
        touch_user_last_seen(user)
        if not company.members.filter(pk=user.pk).exists():
            return Response({'error': 'Forbidden for this company.'}, status=status.HTTP_403_FORBIDDEN)

        payload = _issue_shellui_tokens(
            user,
            company=company,
            avatar_url=prior_avatar,
            prior_app_metadata=prior_app if isinstance(prior_app, dict) else None,
        )
        return Response(payload)


@extend_schema_view(
    post=extend_schema(
        tags=['auth'],
        summary='Logout current session',
        description='ShellUI-compatible logout endpoint. Returns success response for client sign-out flow.',
        responses={200: OpenApiResponse(description='Logout acknowledged')},
    ),
)
class ShellUILogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        _company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err
        return Response({'success': True})


@extend_schema_view(
    get=extend_schema(
        tags=['auth'],
        summary='Get current user profile and metadata',
        description=(
            'Return authenticated user identity plus app_metadata/user_metadata. '
            'Requires bearer access token.'
        ),
        responses={
            200: OpenApiResponse(description='ShellUI user payload with metadata and preferences'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
        },
    ),
    put=extend_schema(
        tags=['auth'],
        summary='Update current user metadata',
        description=(
            'Merge metadata from request.data into cached user_metadata. '
            'If shelluiPreferences are present, they are validated and persisted to UserPreference.'
        ),
        responses={
            200: OpenApiResponse(description='Updated user payload with merged metadata'),
            400: OpenApiResponse(description='Request body must include object field `data`'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
        },
    ),
)
class ShellUIUserView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        company, company_err = _required_company_from_request(request, user=user)
        if company_err:
            return company_err
        user = User.objects.select_related('activity').get(pk=user.pk)
        cache_key = f"shellui:user_metadata:{user.id}"
        user_metadata = cache.get(cache_key) or {
            'name': user.get_full_name() or user.get_username(),
            'full_name': user.get_full_name() or user.get_username(),
            'avatar_url': None,
            'is_staff': bool(user.is_staff),
        }
        user_metadata['is_staff'] = bool(user.is_staff)
        user_metadata['is_company_owner'] = _is_user_company_owner(user, company)
        user_metadata['shelluiPreferences'] = _user_preferences_payload(user)
        user_metadata['groups'] = _user_group_names(user, company)
        user_metadata['last_seen_at'] = _last_seen_at_for_user(user)
        _enrich_user_metadata_avatar(user, user_metadata)
        return Response(
            {
                'id': str(user.id),
                'email': user.email,
                'app_metadata': {'provider': 'django', 'company_id': company.id},
                'user_metadata': user_metadata,
            }
        )

    def put(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        company, company_err = _required_company_from_request(request, user=user)
        if company_err:
            return company_err
        user = User.objects.select_related('activity').get(pk=user.pk)
        data = request.data.get('data')
        if not isinstance(data, dict):
            return Response(
                {'error': 'Expected JSON body with object field `data`.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        data = {k: v for k, v in data.items() if k not in _SHELLUI_JWT_PRIVILEGED_METADATA_KEYS}
        cache_key = f"shellui:user_metadata:{user.id}"
        current = cache.get(cache_key) or {}
        merged = {**current, **data}
        incoming_preferences = merged.get('shelluiPreferences')
        if isinstance(incoming_preferences, dict):
            serializer = UserPreferenceSerializer(data=incoming_preferences)
            if serializer.is_valid():
                preference, _ = UserPreference.objects.get_or_create(user=user)
                validated = serializer.validated_data
                if 'themeName' in validated:
                    preference.theme_name = validated['themeName']
                if 'language' in validated:
                    preference.language = validated['language']
                if 'region' in validated:
                    preference.region = validated['region']
                if 'colorScheme' in validated:
                    preference.color_scheme = validated['colorScheme']
                preference.save()
                merged['shelluiPreferences'] = _user_preferences_payload(user)
        else:
            merged['shelluiPreferences'] = _user_preferences_payload(user)
        merged['groups'] = _user_group_names(user, company)
        merged.pop('last_seen_at', None)
        merged['last_seen_at'] = _last_seen_at_for_user(user)
        merged['is_staff'] = bool(user.is_staff)
        merged['is_company_owner'] = _is_user_company_owner(user, company)
        _enrich_user_metadata_avatar(user, merged)
        cache.set(cache_key, merged, timeout=60 * 60 * 24 * 30)
        return Response(
            {
                'id': str(user.id),
                'email': user.email,
                'app_metadata': {'provider': 'django', 'company_id': company.id},
                'user_metadata': merged,
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['auth'],
        summary='Get current user preferences',
        description='Return persisted ShellUI preferences for the authenticated user.',
        responses={
            200: OpenApiResponse(description='Current preferences payload'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
        },
    ),
    put=extend_schema(
        tags=['auth'],
        summary='Upsert current user preferences',
        description='Validate and persist partial or full preference payload for authenticated user.',
        request=UserPreferenceSerializer,
        responses={
            200: OpenApiResponse(description='Updated preferences payload'),
            400: OpenApiResponse(description='Invalid preference payload'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
        },
    ),
    delete=extend_schema(
        tags=['auth'],
        summary='Delete current user preferences',
        description='Delete persisted preferences for the authenticated user.',
        responses={
            204: OpenApiResponse(description='Preferences deleted'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
        },
    ),
)
class ShellUIPreferenceView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        _company, company_err = _required_company_from_request(request, user=user)
        if company_err:
            return company_err

        return Response(_user_preferences_payload(user), status=status.HTTP_200_OK)

    def put(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        _company, company_err = _required_company_from_request(request, user=user)
        if company_err:
            return company_err

        serializer = UserPreferenceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        preference, _ = UserPreference.objects.get_or_create(user=user)
        validated = serializer.validated_data
        if 'themeName' in validated:
            preference.theme_name = validated['themeName']
        if 'language' in validated:
            preference.language = validated['language']
        if 'region' in validated:
            preference.region = validated['region']
        if 'colorScheme' in validated:
            preference.color_scheme = validated['colorScheme']
        preference.save()
        return Response(_user_preferences_payload(user), status=status.HTTP_200_OK)

    def delete(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        _company, company_err = _required_company_from_request(request, user=user)
        if company_err:
            return company_err

        UserPreference.objects.filter(user=user).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='List users (staff or company owner)',
        description='Paginated directory of users. Requires staff JWT or company-owner membership.',
        parameters=[
            OpenApiParameter(
                name='q',
                type=str,
                location=OpenApiParameter.QUERY,
                description='Search email, username, name, or numeric id.',
            ),
            OpenApiParameter(name='page', type=int, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='page_size', type=int, location=OpenApiParameter.QUERY, required=False),
        ],
    ),
)
class ShellUIAdminUserListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err

        raw_q = request.GET.get('q', '') or ''
        q = raw_q.strip()
        try:
            page = max(1, int(request.GET.get('page') or 1))
            page_size = min(100, max(1, int(request.GET.get('page_size') or 20)))
        except (TypeError, ValueError):
            return Response(
                {'error': 'Invalid page or page_size.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = (
            User.objects.filter(companies=company).distinct().order_by('-id').select_related('activity').prefetch_related('groups')
        )
        if q:
            q_filter = (
                Q(email__icontains=q)
                | Q(username__icontains=q)
                | Q(first_name__icontains=q)
                | Q(last_name__icontains=q)
            )
            if q.isdigit():
                q_filter |= Q(pk=int(q))
            qs = qs.filter(q_filter)

        total = qs.count()
        start = (page - 1) * page_size
        results = [_admin_user_payload(u, company) for u in qs[start : start + page_size]]
        return Response(
            {
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': results,
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='Retrieve user (staff or company owner)',
        description='Single user with ShellUI metadata. Requires staff JWT or company-owner membership.',
    ),
    put=extend_schema(
        tags=['auth-admin'],
        summary='Update user (staff or company owner)',
        description=(
            'Update Django user fields and/or merge `data` into cached user_metadata (same shape as '
            'PUT /auth/v1/user). Staff may change is_staff and is_active. Staff and company owners '
            'may change first_name, last_name, group_ids (within this company), and `data`.'
        ),
        request=ShellUIAdminUserUpdateSerializer,
    ),
)
class ShellUIAdminUserDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            target = User.objects.select_related('activity').get(pk=pk, companies=company)
        except User.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_admin_user_payload(target, company))

    def put(self, request, pk):
        actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            target = User.objects.select_related('activity').get(pk=pk, companies=company)
        except User.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ShellUIAdminUserUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        if not actor.is_staff and any(k in validated for k in ('is_staff', 'is_active')):
            return Response(
                {
                    'error': 'Only staff may change is_staff or is_active.',
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        if target.pk == actor.pk:
            if validated.get('is_staff') is False:
                return Response(
                    {'error': 'You cannot remove your own staff status.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if validated.get('is_active') is False:
                return Response(
                    {'error': 'You cannot deactivate your own account.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        update_fields: list[str] = []
        if 'first_name' in validated:
            target.first_name = validated['first_name']
            update_fields.append('first_name')
        if 'last_name' in validated:
            target.last_name = validated['last_name']
            update_fields.append('last_name')
        if 'is_staff' in validated:
            target.is_staff = validated['is_staff']
            update_fields.append('is_staff')
        if 'is_active' in validated:
            target.is_active = validated['is_active']
            update_fields.append('is_active')
        if update_fields:
            target.save(update_fields=list(dict.fromkeys(update_fields)))

        if 'group_ids' in validated:
            requested_ids = set(validated['group_ids'])
            company_groups = CompanyGroup.objects.filter(company=company).order_by('id')
            existing_ids = set(company_groups.values_list('id', flat=True))
            missing_ids = sorted(requested_ids - existing_ids)
            if missing_ids:
                return Response(
                    {'error': f'Unknown group ids for this company: {missing_ids}.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            for g in company_groups:
                if g.id in requested_ids:
                    g.members.add(target)
                else:
                    g.members.remove(target)

        data = validated.get('data')
        if isinstance(data, dict):
            data = {k: v for k, v in data.items() if k not in _SHELLUI_JWT_PRIVILEGED_METADATA_KEYS}
            cache_key = f"shellui:user_metadata:{target.id}"
            current = cache.get(cache_key) or {}
            merged = {**current, **data}
            merged.pop('last_seen_at', None)
            merged['is_staff'] = bool(target.is_staff)
            merged['is_company_owner'] = _is_user_company_owner(target, company)
            cache.set(cache_key, merged, timeout=60 * 60 * 24 * 30)
            incoming_preferences = merged.get('shelluiPreferences')
            if isinstance(incoming_preferences, dict):
                pref_serializer = UserPreferenceSerializer(data=incoming_preferences)
                if pref_serializer.is_valid():
                    preference, _ = UserPreference.objects.get_or_create(user=target)
                    pvalidated = pref_serializer.validated_data
                    if 'themeName' in pvalidated:
                        preference.theme_name = pvalidated['themeName']
                    if 'language' in pvalidated:
                        preference.language = pvalidated['language']
                    if 'region' in pvalidated:
                        preference.region = pvalidated['region']
                    if 'colorScheme' in pvalidated:
                        preference.color_scheme = pvalidated['colorScheme']
                    preference.save()
                    merged['shelluiPreferences'] = _user_preferences_payload(target)
            else:
                merged['shelluiPreferences'] = _user_preferences_payload(target)

        return Response(_admin_user_payload(target, company))


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='List auth groups (staff or company owner)',
        description='All company groups for requested company with `user_count`.',
    ),
    post=extend_schema(
        tags=['auth-admin'],
        summary='Create auth group (staff or company owner)',
        description='Create a named group.',
        request=ShellUIAdminGroupCreateSerializer,
    ),
)
class ShellUIAdminGroupListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        rows = list(
            CompanyGroup.objects.filter(company=company)
            .annotate(user_count=Count('members', distinct=True))
            .values('id', 'name', 'user_count')
            .order_by('name')
        )
        return Response(rows)

    def post(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        serializer = ShellUIAdminGroupCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = str(serializer.validated_data['name']).strip()
        if not name:
            return Response({'error': 'Group name is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if CompanyGroup.objects.filter(company=company, name=name).exists():
            return Response(
                {'error': 'A group with this name already exists.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        g = CompanyGroup.objects.create(company=company, name=name)
        return Response({'id': g.id, 'name': g.name, 'user_count': 0}, status=status.HTTP_201_CREATED)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='Retrieve auth group (staff or company owner)',
    ),
    put=extend_schema(
        tags=['auth-admin'],
        summary='Rename auth group (staff or company owner)',
        request=ShellUIAdminGroupUpdateSerializer,
    ),
    delete=extend_schema(
        tags=['auth-admin'],
        summary='Delete auth group (staff or company owner)',
    ),
)
class ShellUIAdminGroupDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            g = CompanyGroup.objects.filter(company=company).annotate(user_count=Count('members', distinct=True)).get(pk=pk)
        except CompanyGroup.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'id': g.id, 'name': g.name, 'user_count': g.user_count})

    def put(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            g = CompanyGroup.objects.filter(company=company).annotate(user_count=Count('members', distinct=True)).get(pk=pk)
        except CompanyGroup.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = ShellUIAdminGroupUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = str(serializer.validated_data['name']).strip()
        if not name:
            return Response({'error': 'Group name is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if CompanyGroup.objects.filter(company=company, name=name).exclude(pk=g.pk).exists():
            return Response(
                {'error': 'A group with this name already exists.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        g.name = name
        g.save(update_fields=['name'])
        g = CompanyGroup.objects.filter(company=company).annotate(user_count=Count('members', distinct=True)).get(pk=g.pk)
        return Response({'id': g.id, 'name': g.name, 'user_count': g.user_count})

    def delete(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            g = CompanyGroup.objects.filter(company=company).get(pk=pk)
        except CompanyGroup.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        g.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='List company OAuth clients (staff or company owner)',
        description='All OAuth client keys for the active company, grouped by provider in UI clients.',
    ),
    post=extend_schema(
        tags=['auth-admin'],
        summary='Create company OAuth client (staff or company owner)',
        request=ShellUIAdminOAuthClientCreateSerializer,
    ),
)
class ShellUIAdminOAuthClientListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        rows = CompanyOAuthClient.objects.filter(company=company).select_related('social_app').order_by(
            'social_app__provider',
            'social_app__name',
            'id',
        )
        return Response([_oauth_client_payload(r) for r in rows])

    def post(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        serializer = ShellUIAdminOAuthClientCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        enabled = set(_oauth_providers_from_settings())
        try:
            social_app = SocialApp.objects.get(pk=validated['social_app_id'])
        except SocialApp.DoesNotExist:
            return Response({'error': 'SocialApp not found.'}, status=status.HTTP_400_BAD_REQUEST)
        if str(social_app.provider).strip().lower() not in enabled:
            return Response(
                {'error': f"Provider '{social_app.provider}' is not enabled in settings."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not str(social_app.client_id).strip() or not str(social_app.secret).strip():
            return Response(
                {'error': 'Selected SocialApp is missing client_id or secret.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            row = CompanyOAuthClient.objects.create(
                company=company,
                social_app=social_app,
                is_active=bool(validated.get('is_active', True)),
            )
        except IntegrityError:
            return Response(
                {'error': 'This SocialApp is already mapped for this company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(_oauth_client_payload(row), status=status.HTTP_201_CREATED)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='List available allauth SocialApps for OAuth setup (staff or company owner)',
        description=(
            'Returns all SocialApp rows for providers enabled in settings, plus whether each app '
            'is already linked to the active company OAuth mappings.'
        ),
    ),
    post=extend_schema(
        tags=['auth-admin'],
        summary='Create SocialApp OAuth key and optionally map to company',
        request=ShellUIAdminOAuthSocialAppCreateSerializer,
    ),
)
class ShellUIAdminOAuthSocialAppListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        enabled_providers = set(_oauth_providers_from_settings())
        apps = SocialApp.objects.all().order_by('provider', 'name', 'id')
        rows = [
            _oauth_social_app_payload(company, app)
            for app in apps
            if str(app.provider).strip().lower() in enabled_providers
        ]
        return Response(
            {
                'providers': sorted(enabled_providers),
                'social_apps': rows,
            }
        )

    def post(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        serializer = ShellUIAdminOAuthSocialAppCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        provider = str(validated['provider']).strip().lower()
        if provider not in set(_oauth_providers_from_settings()):
            return Response(
                {'error': f"Provider '{provider}' is not enabled in settings."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if CompanyOAuthClient.objects.filter(company=company, social_app__provider=provider).exists():
            return Response(
                {'error': f"Provider '{provider}' is already configured for this company."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        social_settings = {}
        tenant = str(validated.get('tenant') or '').strip()
        if tenant:
            social_settings = {'tenant': tenant}
        app = SocialApp.objects.create(
            provider=provider,
            name=_generated_social_app_name(provider, company),
            client_id=str(validated['client_id']).strip(),
            secret=str(validated['client_secret']).strip(),
            key='',
            settings=social_settings,
        )
        try:
            current_site = Site.objects.get_current()
            app.sites.add(current_site)
        except Exception:
            pass
        mapping, _created = CompanyOAuthClient.objects.get_or_create(
            company=company,
            social_app=app,
            defaults={'is_active': True},
        )
        return Response(
            {
                'social_app': _oauth_social_app_payload(company, app),
                'mapping': _oauth_client_payload(mapping) if mapping else None,
            },
            status=status.HTTP_201_CREATED,
        )


@extend_schema_view(
    delete=extend_schema(
        tags=['auth-admin'],
        summary='Delete SocialApp OAuth key for this company',
        description=(
            'Deletes the company mapping and the underlying SocialApp. '
            'For safety, deletion is blocked when the SocialApp is mapped to another company.'
        ),
    ),
)
class ShellUIAdminOAuthSocialAppDetailView(APIView):
    permission_classes = [AllowAny]

    def put(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            app = SocialApp.objects.get(pk=pk)
        except SocialApp.DoesNotExist:
            return Response({'error': 'SocialApp not found.'}, status=status.HTTP_404_NOT_FOUND)
        mapping = CompanyOAuthClient.objects.filter(company=company, social_app=app).first()
        if not mapping:
            return Response(
                {'error': 'This SocialApp is not mapped to the current company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = ShellUIAdminOAuthSocialAppUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        if 'client_id' in validated:
            app.client_id = str(validated['client_id']).strip()
        if 'client_secret' in validated:
            app.secret = str(validated['client_secret']).strip()
        settings_data = app.settings if isinstance(app.settings, dict) else {}
        settings_data = dict(settings_data)
        if 'tenant' in validated:
            tenant = str(validated['tenant']).strip()
            if tenant:
                settings_data['tenant'] = tenant
            else:
                settings_data.pop('tenant', None)
        app.settings = settings_data
        app.save()
        app.refresh_from_db()
        return Response(_oauth_social_app_payload(company, app))

    def delete(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            app = SocialApp.objects.get(pk=pk)
        except SocialApp.DoesNotExist:
            return Response({'error': 'SocialApp not found.'}, status=status.HTTP_404_NOT_FOUND)
        mapping = CompanyOAuthClient.objects.filter(company=company, social_app=app).first()
        if not mapping:
            return Response(
                {'error': 'This SocialApp is not mapped to the current company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        has_other_company_mappings = CompanyOAuthClient.objects.filter(social_app=app).exclude(company=company).exists()
        if has_other_company_mappings:
            return Response(
                {'error': 'Cannot delete this key because it is mapped to another company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        app.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='Retrieve company OAuth client (staff or company owner)',
    ),
    put=extend_schema(
        tags=['auth-admin'],
        summary='Update company OAuth client (staff or company owner)',
        request=ShellUIAdminOAuthClientUpdateSerializer,
    ),
    delete=extend_schema(
        tags=['auth-admin'],
        summary='Delete company OAuth client (staff or company owner)',
    ),
)
class ShellUIAdminOAuthClientDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = CompanyOAuthClient.objects.get(pk=pk, company=company)
        except CompanyOAuthClient.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_oauth_client_payload(row))

    def put(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = CompanyOAuthClient.objects.get(pk=pk, company=company)
        except CompanyOAuthClient.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = ShellUIAdminOAuthClientUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        if 'social_app_id' in validated:
            enabled = set(_oauth_providers_from_settings())
            try:
                social_app = SocialApp.objects.get(pk=validated['social_app_id'])
            except SocialApp.DoesNotExist:
                return Response({'error': 'SocialApp not found.'}, status=status.HTTP_400_BAD_REQUEST)
            if str(social_app.provider).strip().lower() not in enabled:
                return Response(
                    {'error': f"Provider '{social_app.provider}' is not enabled in settings."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if not str(social_app.client_id).strip() or not str(social_app.secret).strip():
                return Response(
                    {'error': 'Selected SocialApp is missing client_id or secret.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            row.social_app = social_app
        if 'is_active' in validated:
            row.is_active = validated['is_active']
        try:
            row.save()
        except IntegrityError:
            return Response(
                {'error': 'This SocialApp is already mapped for this company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        row.refresh_from_db()
        return Response(_oauth_client_payload(row))

    def delete(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = CompanyOAuthClient.objects.get(pk=pk, company=company)
        except CompanyOAuthClient.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        row.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='List login audit events (staff or company owner)',
        description=(
            'Paginated OAuth sign-in attempts (success and failure). '
            'Contains privacy-oriented fields (hashed IP, truncated user-agent). '
        ),
        parameters=[
            OpenApiParameter(
                name='user_id',
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Filter by Django user id.',
            ),
            OpenApiParameter(
                name='outcome',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='success or failure.',
            ),
            OpenApiParameter(
                name='provider',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='OAuth provider slug (github, google, microsoft).',
            ),
            OpenApiParameter(
                name='is_staff_at_event',
                type=bool,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Filter rows where the user was staff at login time.',
            ),
            OpenApiParameter(
                name='created_after',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='ISO 8601 datetime (inclusive lower bound).',
            ),
            OpenApiParameter(
                name='created_before',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='ISO 8601 datetime (exclusive upper bound).',
            ),
            OpenApiParameter(
                name='client_country',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Case-insensitive substring match on GeoIP country (stored value).',
            ),
            OpenApiParameter(
                name='client_city',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Case-insensitive substring match on GeoIP city.',
            ),
            OpenApiParameter(
                name='client_timezone',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Case-insensitive substring match on client IANA timezone.',
            ),
            OpenApiParameter(
                name='language',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    "Filter rows where the user's saved ShellUI preference language matches "
                    '(e.g. en, fr). Omits anonymous events (no user).'
                ),
            ),
            OpenApiParameter(name='page', type=int, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='page_size', type=int, location=OpenApiParameter.QUERY, required=False),
        ],
        responses={200: OpenApiResponse(description='Paginated list of login audit events')},
    ),
)
class ShellUIAdminLoginEventListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err

        try:
            page = max(1, int(request.GET.get('page') or 1))
            page_size = min(100, max(1, int(request.GET.get('page_size') or 20)))
        except (TypeError, ValueError):
            return Response(
                {'error': 'Invalid page or page_size.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = LoginEvent.objects.filter(company=company).select_related('user').order_by('-created_at', '-id')

        uid = request.GET.get('user_id')
        if uid is not None and str(uid).strip():
            try:
                qs = qs.filter(user_id=int(uid))
            except (TypeError, ValueError):
                return Response({'error': 'Invalid user_id.'}, status=status.HTTP_400_BAD_REQUEST)

        outcome = (request.GET.get('outcome') or '').strip().lower()
        if outcome:
            if outcome not in (LoginEvent.OUTCOME_SUCCESS, LoginEvent.OUTCOME_FAILURE):
                return Response({'error': 'Invalid outcome.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(outcome=outcome)

        prov = (request.GET.get('provider') or '').strip().lower()
        if prov:
            qs = qs.filter(provider=prov)

        staff_raw = request.GET.get('is_staff_at_event')
        if staff_raw is not None and str(staff_raw).strip() != '':
            s = str(staff_raw).strip().lower()
            if s in ('1', 'true', 'yes'):
                qs = qs.filter(is_staff_at_event=True)
            elif s in ('0', 'false', 'no'):
                qs = qs.filter(is_staff_at_event=False)
            else:
                return Response(
                    {'error': 'Invalid is_staff_at_event (use true or false).'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        ca = (request.GET.get('created_after') or '').strip()
        if ca:
            dt = parse_datetime(ca)
            if not dt:
                return Response({'error': 'Invalid created_after.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(created_at__gte=dt)

        cb = (request.GET.get('created_before') or '').strip()
        if cb:
            dt = parse_datetime(cb)
            if not dt:
                return Response({'error': 'Invalid created_before.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(created_at__lt=dt)

        cc = (request.GET.get('client_country') or '').strip()
        if cc:
            qs = qs.filter(client_country__icontains=cc)

        city = (request.GET.get('client_city') or '').strip()
        if city:
            qs = qs.filter(client_city__icontains=city)

        ctz = (request.GET.get('client_timezone') or '').strip()
        if ctz:
            qs = qs.filter(client_timezone__icontains=ctz)

        lang = (request.GET.get('language') or '').strip().lower()
        if lang:
            allowed_lang = {choice[0] for choice in UserPreference.LANGUAGE_CHOICES}
            if lang not in allowed_lang:
                return Response({'error': 'Invalid language.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(user__preference__language=lang)

        total = qs.count()
        start = (page - 1) * page_size
        rows = [_login_event_payload(e) for e in qs[start : start + page_size]]
        return Response(
            {
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': rows,
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='Retrieve login audit event (staff or company owner)',
        description='Single login event row.',
        responses={200: OpenApiResponse(description='Login audit event')},
    ),
)
class ShellUIAdminLoginEventDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            event = LoginEvent.objects.select_related('user').get(pk=pk, company=company)
        except LoginEvent.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_login_event_payload(event))


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='Prometheus metrics (staff or company owner)',
        description=(
            'Prometheus text exposition (openmetrics) for the requested company. '
            'Requires Bearer token (staff or company owner).'
        ),
        responses={200: OpenApiResponse(description='text/plain Prometheus exposition')},
    ),
)
class ShellUIAdminMetricsView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = DEFAULT_METRICS_RENDERERS

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        return HttpResponse(
            auth_metrics.metrics_http_body(company_id=company.id),
            content_type=auth_metrics.METRICS_CONTENT_TYPE,
        )


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='Prometheus metrics for all companies (staff)',
        description='Global Prometheus text exposition across all companies; staff users only.',
        responses={200: OpenApiResponse(description='text/plain Prometheus exposition')},
    ),
)
class ShellUIAdminGlobalMetricsView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = DEFAULT_METRICS_RENDERERS

    def get(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        if not user.is_staff:
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        return HttpResponse(
            auth_metrics.metrics_http_body(),
            content_type=auth_metrics.METRICS_CONTENT_TYPE,
        )
