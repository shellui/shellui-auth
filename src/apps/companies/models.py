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
