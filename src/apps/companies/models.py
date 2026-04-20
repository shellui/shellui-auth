from django.conf import settings
from django.db import models
from django.utils.text import slugify


class Company(models.Model):
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='companies',
        blank=True,
    )
    owners = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='owned_companies',
        blank=True,
    )

    class Meta:
        ordering = ['name']

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name)
            candidate = base_slug
            suffix = 1
            while Company.objects.filter(slug=candidate).exclude(pk=self.pk).exists():
                candidate = f'{base_slug}-{suffix}'
                suffix += 1
            self.slug = candidate
        super().save(*args, **kwargs)


class CompanyGroup(models.Model):
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name='groups',
    )
    name = models.CharField(max_length=150)
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='company_groups',
        blank=True,
    )

    class Meta:
        ordering = ['name']
        constraints = [
            models.UniqueConstraint(fields=['company', 'name'], name='company_group_unique_name_per_company'),
        ]

    def __str__(self) -> str:
        return f'{self.company_id}:{self.name}'


class CompanyOAuthRedirect(models.Model):
    """
    Allowed absolute URL prefix for OAuth browser flows (`redirect_to` query param).
    Tokens are appended as a URL fragment; only matching destinations are permitted.
    """

    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name='oauth_redirect_allowlist',
    )
    base_url = models.CharField(max_length=500)
    label = models.CharField(max_length=150, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['id']
        constraints = [
            models.UniqueConstraint(
                fields=['company', 'base_url'],
                name='company_oauth_redirect_unique_base_per_company',
            ),
        ]

    def __str__(self) -> str:
        return f'{self.company_id}:{self.base_url}'

    def save(self, *args, **kwargs):
        from .redirect_allowlist import normalize_stored_base_url

        self.base_url = normalize_stored_base_url(self.base_url)
        super().save(*args, **kwargs)
