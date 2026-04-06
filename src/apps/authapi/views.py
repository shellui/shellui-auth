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
from django.contrib.auth.models import Group
from django.contrib.auth.signals import user_logged_in
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
from .renderers import DEFAULT_METRICS_RENDERERS
from .login_audit import oauth_callback_url, record_login_event
from .models import LoginEvent, UserPreference
from .user_activity import touch_user_last_seen
from .oauth import build_authorize_url, exchange_code_for_token, fetch_provider_userinfo, get_provider_config
from .serializers import (
    ProviderAuthorizeSerializer,
    ProviderCallbackSerializer,
    ShellUIAdminGroupCreateSerializer,
    ShellUIAdminGroupUpdateSerializer,
    ShellUIAdminUserUpdateSerializer,
    UserPreferenceSerializer,
)

User = get_user_model()
FRONTEND_DEFAULT_REDIRECT_PATH = '/login/callback'


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


def _user_group_names(user: User) -> list[str]:
    return list(user.groups.values_list('name', flat=True).order_by('name'))


def _admin_user_group_rows(user: User) -> list[dict]:
    return list(user.groups.values('id', 'name').order_by('name'))


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


def _issue_tokens(user: User) -> dict:
    user_payload = {
        'id': user.id,
        'email': user.email,
        'username': user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
    }
    refresh = RefreshToken.for_user(user)
    refresh['user'] = user_payload
    access = refresh.access_token
    access['user'] = user_payload
    return {
        'refresh': str(refresh),
        'access': str(access),
        'user': user_payload,
    }


def _enabled_oauth_providers() -> list[str]:
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


def _issue_shellui_tokens(
    user: User,
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
        'shelluiPreferences': preferences,
        'groups': _user_group_names(user),
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
    access['user_metadata'] = user_metadata
    access['app_metadata'] = app_metadata
    refresh['user_metadata'] = user_metadata
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


def _resolve_redirect_to(request) -> str:
    redirect_to = request.GET.get('redirect_to', '').strip()
    if redirect_to:
        return redirect_to
    return f"{request.scheme}://{request.get_host()}{FRONTEND_DEFAULT_REDIRECT_PATH}"


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


def _require_staff(request):
    user = _authenticate_bearer_user(request)
    if not user:
        return None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    if not user.is_staff:
        return None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
    return user, None


def _login_event_payload(event: LoginEvent) -> dict:
    return {
        'id': event.id,
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


def _admin_user_payload(user: User) -> dict:
    cache_key = f"shellui:user_metadata:{user.id}"
    user_metadata = cache.get(cache_key) or {
        'name': user.get_full_name() or user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
        'avatar_url': None,
        'is_staff': bool(user.is_staff),
    }
    user_metadata['is_staff'] = bool(user.is_staff)
    user_metadata['shelluiPreferences'] = _user_preferences_payload(user)
    group_rows = _admin_user_group_rows(user)
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
        serializer = ProviderAuthorizeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        authorize_url = build_authorize_url(
            provider=provider,
            redirect_uri=serializer.validated_data['redirect_uri'],
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
        serializer = ProviderCallbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        client_tz = serializer.validated_data.get('client_timezone') or ''
        client_dev = serializer.validated_data.get('client_device_id') or None
        try:
            access_token = exchange_code_for_token(
                provider=provider,
                code=serializer.validated_data['code'],
                redirect_uri=serializer.validated_data['redirect_uri'],
            )
            userinfo = fetch_provider_userinfo(provider, access_token)
            provider_id, email, full_name, avatar_url = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=None,
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
        auth_metrics.record_successful_login(provider)
        record_login_event(
            request=request,
            outcome=LoginEvent.OUTCOME_SUCCESS,
            provider=provider,
            user=user,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        token_payload = _issue_tokens(user)
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

    def get(self, _request):
        providers = _enabled_oauth_providers()
        external = {provider: True for provider in providers}
        return Response(
            {
                'methods': ['oauth'] if providers else [],
                'oauthProviders': providers,
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
        provider = request.GET.get('provider', '').strip().lower()
        if not provider:
            return Response({'error': 'Missing provider parameter.'}, status=status.HTTP_400_BAD_REQUEST)
        if provider not in _enabled_oauth_providers():
            return Response(
                {'error': f"Provider '{provider}' is not enabled."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        cfg = get_provider_config(provider)
        if not str(cfg.client_id).strip() or not str(cfg.client_secret).strip():
            return Response(
                {
                    'error': (
                        f"Provider '{provider}' is missing OAuth credentials. "
                        f"Set {provider.upper()}_CLIENT_ID/{provider.upper()}_CLIENT_SECRET "
                        f"or configure an allauth SocialApp with client id + secret."
                    )
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        redirect_to = _resolve_redirect_to(request)
        callback_url = oauth_callback_url(request, provider, redirect_to)
        authorize_url = build_authorize_url(provider=provider, redirect_uri=callback_url)
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
        provider = request.GET.get('provider', '').strip().lower()
        code = request.GET.get('code', '').strip()
        redirect_to = _resolve_redirect_to(request)
        if not provider or not code:
            return Response({'error': 'Missing provider or code.'}, status=status.HTTP_400_BAD_REQUEST)
        callback_url = oauth_callback_url(request, provider, redirect_to)
        client_tz = request.GET.get('client_timezone', '')
        client_dev = request.GET.get('client_device_id', '') or None
        try:
            access_token = exchange_code_for_token(provider=provider, code=code, redirect_uri=callback_url)
            userinfo = fetch_provider_userinfo(provider, access_token)
            provider_id, email, full_name, avatar_url = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=None,
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
        payload = _issue_shellui_tokens(user, avatar_url=avatar_url, oauth_provider=provider)
        auth_metrics.record_successful_login(provider)
        record_login_event(
            request=request,
            outcome=LoginEvent.OUTCOME_SUCCESS,
            provider=provider,
            user=user,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        return HttpResponseRedirect(_build_callback_redirect(redirect_to, payload, provider=provider))


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
        payload = _issue_shellui_tokens(
            user,
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

    def post(self, _request):
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
        user = User.objects.select_related('activity').get(pk=user.pk)
        cache_key = f"shellui:user_metadata:{user.id}"
        user_metadata = cache.get(cache_key) or {
            'name': user.get_full_name() or user.get_username(),
            'full_name': user.get_full_name() or user.get_username(),
            'avatar_url': None,
            'is_staff': bool(user.is_staff),
        }
        user_metadata['is_staff'] = bool(user.is_staff)
        user_metadata['shelluiPreferences'] = _user_preferences_payload(user)
        user_metadata['groups'] = _user_group_names(user)
        user_metadata['last_seen_at'] = _last_seen_at_for_user(user)
        _enrich_user_metadata_avatar(user, user_metadata)
        return Response(
            {
                'id': str(user.id),
                'email': user.email,
                'app_metadata': {'provider': 'django'},
                'user_metadata': user_metadata,
            }
        )

    def put(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        user = User.objects.select_related('activity').get(pk=user.pk)
        data = request.data.get('data')
        if not isinstance(data, dict):
            return Response(
                {'error': 'Expected JSON body with object field `data`.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        data = {k: v for k, v in data.items() if k != 'groups'}
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
        merged['groups'] = _user_group_names(user)
        merged.pop('last_seen_at', None)
        merged['last_seen_at'] = _last_seen_at_for_user(user)
        _enrich_user_metadata_avatar(user, merged)
        cache.set(cache_key, merged, timeout=60 * 60 * 24 * 30)
        return Response(
            {
                'id': str(user.id),
                'email': user.email,
                'app_metadata': {'provider': 'django'},
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

        return Response(_user_preferences_payload(user), status=status.HTTP_200_OK)

    def put(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

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

        UserPreference.objects.filter(user=user).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='List users (staff)',
        description='Paginated directory of users. Requires staff JWT.',
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
        _staff, err = _require_staff(request)
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

        qs = User.objects.all().order_by('-id').select_related('activity').prefetch_related('groups')
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
        results = [_admin_user_payload(u) for u in qs[start : start + page_size]]
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
        summary='Retrieve user (staff)',
        description='Single user with ShellUI metadata. Requires staff JWT.',
    ),
    put=extend_schema(
        tags=['auth-admin'],
        summary='Update user (staff)',
        description=(
            'Update Django user fields and/or merge `data` into cached user_metadata (same shape as '
            'PUT /auth/v1/user). Requires staff JWT.'
        ),
        request=ShellUIAdminUserUpdateSerializer,
    ),
)
class ShellUIAdminUserDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, pk):
        _staff, err = _require_staff(request)
        if err:
            return err
        try:
            target = User.objects.select_related('activity').get(pk=pk)
        except User.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_admin_user_payload(target))

    def put(self, request, pk):
        staff, err = _require_staff(request)
        if err:
            return err
        try:
            target = User.objects.select_related('activity').get(pk=pk)
        except User.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ShellUIAdminUserUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        if target.pk == staff.pk:
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
            target.groups.set(Group.objects.filter(pk__in=validated['group_ids']))

        data = validated.get('data')
        if isinstance(data, dict):
            data = {k: v for k, v in data.items() if k != 'groups'}
            cache_key = f"shellui:user_metadata:{target.id}"
            current = cache.get(cache_key) or {}
            merged = {**current, **data}
            merged.pop('last_seen_at', None)
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

        return Response(_admin_user_payload(target))


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='List auth groups (staff)',
        description='All Django auth groups (`auth_group`) with `user_count`. Requires staff JWT.',
    ),
    post=extend_schema(
        tags=['auth-admin'],
        summary='Create auth group (staff)',
        description='Create a named group. Requires staff JWT.',
        request=ShellUIAdminGroupCreateSerializer,
    ),
)
class ShellUIAdminGroupListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        _staff, err = _require_staff(request)
        if err:
            return err
        rows = list(
            Group.objects.annotate(user_count=Count('user', distinct=True))
            .values('id', 'name', 'user_count')
            .order_by('name')
        )
        return Response(rows)

    def post(self, request):
        _staff, err = _require_staff(request)
        if err:
            return err
        serializer = ShellUIAdminGroupCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = str(serializer.validated_data['name']).strip()
        if not name:
            return Response({'error': 'Group name is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if Group.objects.filter(name=name).exists():
            return Response(
                {'error': 'A group with this name already exists.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        g = Group.objects.create(name=name)
        return Response({'id': g.id, 'name': g.name, 'user_count': 0}, status=status.HTTP_201_CREATED)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='Retrieve auth group (staff)',
    ),
    put=extend_schema(
        tags=['auth-admin'],
        summary='Rename auth group (staff)',
        request=ShellUIAdminGroupUpdateSerializer,
    ),
    delete=extend_schema(
        tags=['auth-admin'],
        summary='Delete auth group (staff)',
    ),
)
class ShellUIAdminGroupDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, pk):
        _staff, err = _require_staff(request)
        if err:
            return err
        try:
            g = Group.objects.annotate(user_count=Count('user', distinct=True)).get(pk=pk)
        except Group.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'id': g.id, 'name': g.name, 'user_count': g.user_count})

    def put(self, request, pk):
        _staff, err = _require_staff(request)
        if err:
            return err
        try:
            g = Group.objects.annotate(user_count=Count('user', distinct=True)).get(pk=pk)
        except Group.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = ShellUIAdminGroupUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = str(serializer.validated_data['name']).strip()
        if not name:
            return Response({'error': 'Group name is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if Group.objects.filter(name=name).exclude(pk=g.pk).exists():
            return Response(
                {'error': 'A group with this name already exists.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        g.name = name
        g.save(update_fields=['name'])
        g = Group.objects.annotate(user_count=Count('user', distinct=True)).get(pk=g.pk)
        return Response({'id': g.id, 'name': g.name, 'user_count': g.user_count})

    def delete(self, request, pk):
        _staff, err = _require_staff(request)
        if err:
            return err
        try:
            g = Group.objects.get(pk=pk)
        except Group.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        g.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='List login audit events (staff)',
        description=(
            'Paginated OAuth sign-in attempts (success and failure). '
            'Contains privacy-oriented fields (hashed IP, truncated user-agent). '
            'Requires staff JWT.'
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
        _staff, err = _require_staff(request)
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

        qs = LoginEvent.objects.all().select_related('user').order_by('-created_at', '-id')

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
        summary='Retrieve login audit event (staff)',
        description='Single login event row. Requires staff JWT.',
        responses={200: OpenApiResponse(description='Login audit event')},
    ),
)
class ShellUIAdminLoginEventDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, pk):
        _staff, err = _require_staff(request)
        if err:
            return err
        try:
            event = LoginEvent.objects.select_related('user').get(pk=pk)
        except LoginEvent.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_login_event_payload(event))


@extend_schema_view(
    get=extend_schema(
        tags=['auth-admin'],
        summary='Prometheus metrics (staff)',
        description=(
            'Prometheus text exposition (openmetrics). Requires staff JWT in Authorization: Bearer. '
            'Use from the admin UI or, later, automation with a service token; the route is not public.'
        ),
        responses={200: OpenApiResponse(description='text/plain Prometheus exposition')},
    ),
)
class ShellUIAdminMetricsView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = DEFAULT_METRICS_RENDERERS

    def get(self, request):
        _staff, err = _require_staff(request)
        if err:
            return err
        return HttpResponse(
            auth_metrics.metrics_http_body(),
            content_type=auth_metrics.METRICS_CONTENT_TYPE,
        )
