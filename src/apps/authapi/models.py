from django.conf import settings
from django.db import models


class LoginEvent(models.Model):
    """
    Security audit trail for OAuth sign-in outcomes.

    Privacy notes:
    - IP is stored only as a salted hash (correlation / abuse detection, not exact location).
    - User-Agent is truncated; optional client device id is stored hashed.
    - Optional `client_timezone` is IANA zone from the client (coarse; not GPS).
    - `client_country` / `client_city` come from optional GeoIP lookup against the client IP;
      leave empty when no database is configured or lookup fails.
    """

    OUTCOME_SUCCESS = 'success'
    OUTCOME_FAILURE = 'failure'
    OUTCOME_CHOICES = [
        (OUTCOME_SUCCESS, 'Success'),
        (OUTCOME_FAILURE, 'Failure'),
    ]

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='login_events',
    )
    outcome = models.CharField(max_length=16, choices=OUTCOME_CHOICES, db_index=True)
    provider = models.CharField(max_length=32, db_index=True)
    failure_reason = models.CharField(max_length=255, blank=True)
    is_staff_at_event = models.BooleanField(default=False, db_index=True)
    ip_hash = models.CharField(max_length=64, blank=True, db_index=True)
    user_agent = models.CharField(max_length=512, blank=True)
    client_timezone = models.CharField(max_length=64, blank=True)
    client_device_id_hash = models.CharField(max_length=64, blank=True)
    client_country = models.CharField(
        max_length=64,
        blank=True,
        help_text='ISO country code or name from GeoIP when configured.',
    )
    client_city = models.CharField(
        max_length=128,
        blank=True,
        help_text='City from GeoIP when configured.',
    )

    class Meta:
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['user', '-created_at']),
        ]

    def __str__(self) -> str:
        return f'LoginEvent(id={self.pk}, outcome={self.outcome}, provider={self.provider})'


class UserPreference(models.Model):
    LANGUAGE_EN = 'en'
    LANGUAGE_FR = 'fr'
    LANGUAGE_CHOICES = [
        (LANGUAGE_EN, 'English'),
        (LANGUAGE_FR, 'French'),
    ]

    COLOR_SCHEME_LIGHT = 'light'
    COLOR_SCHEME_DARK = 'dark'
    COLOR_SCHEME_SYSTEM = 'system'
    COLOR_SCHEME_CHOICES = [
        (COLOR_SCHEME_LIGHT, 'Light'),
        (COLOR_SCHEME_DARK, 'Dark'),
        (COLOR_SCHEME_SYSTEM, 'System'),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='preference',
        on_delete=models.CASCADE,
    )
    theme_name = models.CharField(max_length=100, default='default')
    language = models.CharField(max_length=8, choices=LANGUAGE_CHOICES, default=LANGUAGE_EN)
    region = models.CharField(max_length=64, default='UTC')
    color_scheme = models.CharField(
        max_length=16,
        choices=COLOR_SCHEME_CHOICES,
        default=COLOR_SCHEME_SYSTEM,
    )
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['user_id']

    def __str__(self) -> str:
        return f'UserPreference(user_id={self.user_id})'
