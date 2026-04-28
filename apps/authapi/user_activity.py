"""Per-user last_seen_at for activity tracking (OAuth login, admin session login, token refresh)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils import timezone

from .models import UserActivity

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser


def touch_user_last_seen(user: AbstractBaseUser) -> None:
    """Upsert UserActivity.last_seen_at to now (used for MAU and product analytics)."""
    UserActivity.objects.update_or_create(
        user=user,
        defaults={'last_seen_at': timezone.now()},
    )
