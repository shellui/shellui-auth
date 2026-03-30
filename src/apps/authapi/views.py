import json
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlencode

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseRedirect
from django.contrib.auth import get_user_model
from django.db.utils import OperationalError, ProgrammingError
from allauth.socialaccount.models import SocialApp, SocialAccount
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import UserPreference
from .oauth import build_authorize_url, exchange_code_for_token, fetch_provider_userinfo, get_provider_config
from .serializers import ProviderAuthorizeSerializer, ProviderCallbackSerializer, UserPreferenceSerializer

User = get_user_model()
FRONTEND_DEFAULT_REDIRECT_PATH = '/login/callback'


def _user_preferences_payload(user: User) -> dict:
    preference, _ = UserPreference.objects.get_or_create(user=user)
    return {
        'themeName': preference.theme_name,
        'language': preference.language,
        'region': preference.region,
        'colorScheme': preference.color_scheme,
    }


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


def _issue_shellui_tokens(user: User, provider: str, avatar_url: str | None = None) -> dict:
    refresh = RefreshToken.for_user(user)
    preferences = _user_preferences_payload(user)
    resolved_avatar = _resolve_avatar_url_for_jwt(user, avatar_url)
    user_metadata = {
        'name': user.get_full_name() or user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
        'avatar_url': resolved_avatar,
        'shelluiPreferences': preferences,
    }
    app_metadata = {'provider': provider}
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

        try:
            access_token = exchange_code_for_token(
                provider=provider,
                code=serializer.validated_data['code'],
                redirect_uri=serializer.validated_data['redirect_uri'],
            )
            userinfo = fetch_provider_userinfo(provider, access_token)
            provider_id, email, full_name, _avatar_url = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
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

        token_payload = _issue_tokens(user)
        return Response(token_payload, status=status.HTTP_200_OK)


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
        callback_url = (
            f"{request.scheme}://{request.get_host()}/auth/v1/oauth/callback?"
            f"provider={provider}&redirect_to={_resolve_redirect_to(request)}"
        )
        authorize_url = build_authorize_url(provider=provider, redirect_uri=callback_url)
        return HttpResponseRedirect(authorize_url)


class ShellUIOAuthCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        provider = request.GET.get('provider', '').strip().lower()
        code = request.GET.get('code', '').strip()
        redirect_to = _resolve_redirect_to(request)
        if not provider or not code:
            return Response({'error': 'Missing provider or code.'}, status=status.HTTP_400_BAD_REQUEST)
        callback_url = (
            f"{request.scheme}://{request.get_host()}/auth/v1/oauth/callback?"
            f"provider={provider}&redirect_to={redirect_to}"
        )
        try:
            access_token = exchange_code_for_token(provider=provider, code=code, redirect_uri=callback_url)
            userinfo = fetch_provider_userinfo(provider, access_token)
            provider_id, email, full_name, avatar_url = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
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
        payload = _issue_shellui_tokens(user, provider=provider, avatar_url=avatar_url)
        return HttpResponseRedirect(_build_callback_redirect(redirect_to, payload, provider=provider))


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

        payload = _issue_shellui_tokens(user, provider='refresh', avatar_url=prior_avatar)
        return Response(payload)


class ShellUILogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, _request):
        return Response({'success': True})


class ShellUIUserView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        cache_key = f"shellui:user_metadata:{user.id}"
        user_metadata = cache.get(cache_key) or {
            'name': user.get_full_name() or user.get_username(),
            'full_name': user.get_full_name() or user.get_username(),
            'avatar_url': None,
        }
        user_metadata['shelluiPreferences'] = _user_preferences_payload(user)
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
        data = request.data.get('data')
        if not isinstance(data, dict):
            return Response(
                {'error': 'Expected JSON body with object field `data`.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        cache_key = f"shellui:user_metadata:{user.id}"
        current = cache.get(cache_key) or {}
        merged = {**current, **data}
        cache.set(cache_key, merged, timeout=60 * 60 * 24 * 30)
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
        return Response(
            {
                'id': str(user.id),
                'email': user.email,
                'app_metadata': {'provider': 'django'},
                'user_metadata': merged,
            }
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
