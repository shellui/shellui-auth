"""
Record LoginEvent rows for Django admin username/password sign-in (contrib.admin login form).

Uses auth signals so we do not fork or wrap AdminSite. Scoped to requests whose path is the
admin login URL (success and failure).
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.dispatch import receiver

from .login_audit import record_login_event
from .models import LoginEvent

User = get_user_model()

PROVIDER_DJANGO_ADMIN = 'django_admin'


def _is_django_admin_login_path(request) -> bool:
    if not request:
        return False
    path = (getattr(request, 'path', None) or '').rstrip('/')
    return path.endswith('/admin/login')


def _user_from_failed_credentials(credentials: dict | None) -> User | None:
    if not credentials:
        return None
    field = User.USERNAME_FIELD
    username = credentials.get(field) or credentials.get('username')
    if username is None or not str(username).strip():
        return None
    try:
        return User.objects.get(**{field: username})
    except User.DoesNotExist:
        return None


@receiver(user_logged_in)
def login_event_on_admin_session_login(sender, request, user, **kwargs):
    if not _is_django_admin_login_path(request):
        return
    record_login_event(
        request=request,
        outcome=LoginEvent.OUTCOME_SUCCESS,
        provider=PROVIDER_DJANGO_ADMIN,
        user=user,
    )


@receiver(user_login_failed)
def login_event_on_admin_session_login_failed(sender, credentials, request, **kwargs):
    if not _is_django_admin_login_path(request):
        return
    candidate = _user_from_failed_credentials(credentials if isinstance(credentials, dict) else None)
    record_login_event(
        request=request,
        outcome=LoginEvent.OUTCOME_FAILURE,
        provider=PROVIDER_DJANGO_ADMIN,
        user=candidate,
        failure_reason='Invalid credentials',
    )
