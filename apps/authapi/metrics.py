"""Prometheus-style metrics for shellui-auth; exposition is staff JWT–protected (see ShellUIAdminMetricsView)."""

from __future__ import annotations

from datetime import timedelta

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.utils import timezone
from apps.companies.models import Company
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

from .models import UserActivity

_users_total = Gauge('shellui_auth_users_total', 'Number of Django user rows.')
_users_active = Gauge(
    'shellui_auth_users_active',
    'Users with is_active=True.',
)
_users_staff = Gauge(
    'shellui_auth_users_staff',
    'Users with is_staff=True.',
)
_social_accounts_total = Gauge(
    'shellui_auth_social_accounts_total',
    'Linked OAuth social account rows (django-allauth SocialAccount).',
)
_daily_active_users = Gauge(
    'shellui_auth_daily_active_users',
    'Users with last_seen_at on or after midnight at the start of the current calendar day (same tz as timezone.now()).',
)
_weekly_active_users = Gauge(
    'shellui_auth_weekly_active_users',
    'Users with last_seen_at on or after Monday 00:00 of the current ISO calendar week (same tz as timezone.now()).',
)
_monthly_active_users = Gauge(
    'shellui_auth_monthly_active_users',
    'Users with last_seen_at in the current calendar month (timezone-aware now(), typically UTC).',
)

_successful_logins_total = Counter(
    'shellui_auth_successful_logins_total',
    'Successful OAuth login completions since this process started (browser callback or API login).',
    labelnames=('provider', 'company_id'),
)

_company_users_total = Gauge(
    'shellui_auth_company_users_total',
    'Number of users in a company.',
    labelnames=('company_id',),
)
_company_users_active = Gauge(
    'shellui_auth_company_users_active',
    'Number of active users (is_active=True) in a company.',
    labelnames=('company_id',),
)
_company_users_staff = Gauge(
    'shellui_auth_company_users_staff',
    'Number of staff users in a company.',
    labelnames=('company_id',),
)
_company_social_accounts_total = Gauge(
    'shellui_auth_company_social_accounts_total',
    'Linked social account rows for company users.',
    labelnames=('company_id',),
)
_company_daily_active_users = Gauge(
    'shellui_auth_company_daily_active_users',
    'Company users active today.',
    labelnames=('company_id',),
)
_company_weekly_active_users = Gauge(
    'shellui_auth_company_weekly_active_users',
    'Company users active this ISO week.',
    labelnames=('company_id',),
)
_company_monthly_active_users = Gauge(
    'shellui_auth_company_monthly_active_users',
    'Company users active this month.',
    labelnames=('company_id',),
)


def _count_user_activity_since(cutoff) -> int:
    return UserActivity.objects.filter(last_seen_at__gte=cutoff).count()


def _count_company_user_activity_since(company: Company, cutoff) -> int:
    return UserActivity.objects.filter(user__companies=company, last_seen_at__gte=cutoff).distinct().count()


def _daily_active_users_count() -> int:
    now = timezone.now()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return _count_user_activity_since(day_start)


def _weekly_active_users_count() -> int:
    now = timezone.now()
    week_start = (now - timedelta(days=now.weekday())).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return _count_user_activity_since(week_start)


def _monthly_active_users_count() -> int:
    now = timezone.now()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return _count_user_activity_since(month_start)


def refresh_db_gauges() -> None:
    """Sync user-related gauges from the database before Prometheus serialization."""
    User = get_user_model()
    _users_total.set(User.objects.count())
    _users_active.set(User.objects.filter(is_active=True).count())
    _users_staff.set(User.objects.filter(is_staff=True).count())
    _social_accounts_total.set(SocialAccount.objects.count())
    _daily_active_users.set(_daily_active_users_count())
    _weekly_active_users.set(_weekly_active_users_count())
    _monthly_active_users.set(_monthly_active_users_count())


def refresh_company_gauges(company: Company) -> None:
    company_id = str(company.id)
    users = get_user_model().objects.filter(companies=company).distinct()
    now = timezone.now()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    _company_users_total.labels(company_id=company_id).set(users.count())
    _company_users_active.labels(company_id=company_id).set(users.filter(is_active=True).count())
    _company_users_staff.labels(company_id=company_id).set(users.filter(is_staff=True).count())
    _company_social_accounts_total.labels(company_id=company_id).set(
        SocialAccount.objects.filter(user__companies=company).distinct().count()
    )
    _company_daily_active_users.labels(company_id=company_id).set(
        _count_company_user_activity_since(company, day_start)
    )
    _company_weekly_active_users.labels(company_id=company_id).set(
        _count_company_user_activity_since(company, week_start)
    )
    _company_monthly_active_users.labels(company_id=company_id).set(
        _count_company_user_activity_since(company, month_start)
    )


def record_successful_login(provider: str, company_id: int) -> None:
    p = (provider or 'unknown').strip().lower() or 'unknown'
    _successful_logins_total.labels(provider=p, company_id=str(company_id)).inc()


def metrics_http_body(company_id: int | None = None) -> bytes:
    if company_id is None:
        refresh_db_gauges()
    else:
        try:
            company = Company.objects.get(pk=company_id)
        except Company.DoesNotExist:
            refresh_db_gauges()
        else:
            refresh_company_gauges(company)
    return generate_latest()


METRICS_CONTENT_TYPE = CONTENT_TYPE_LATEST
