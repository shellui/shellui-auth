from django.conf import settings
from django.contrib import admin, messages
from django.http import Http404, HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html

from .models import Company, CompanyGroup, CompanyOAuthClient


class CompanyOAuthClientInline(admin.TabularInline):
    model = CompanyOAuthClient
    extra = 1
    fields = ('social_app', 'is_active', 'created_at')
    readonly_fields = ('created_at',)


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'slug', 'oauth_clients_link')
    search_fields = ('name', 'slug')
    filter_horizontal = ('members', 'owners')
    inlines = [CompanyOAuthClientInline]

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                '<int:company_id>/oauth-clients/',
                self.admin_site.admin_view(self.oauth_clients_view),
                name='companies_company_oauth_clients',
            ),
            path(
                '<int:company_id>/oauth-clients/add/<str:provider>/',
                self.admin_site.admin_view(self.oauth_client_add_for_provider_view),
                name='companies_company_oauth_client_add_for_provider',
            ),
        ]
        return custom_urls + urls

    @admin.display(description='OAuth clients')
    def oauth_clients_link(self, obj: Company):
        url = reverse('admin:companies_company_oauth_clients', args=[obj.pk])
        return format_html('<a href="{}">Manage OAuth clients</a>', url)

    @staticmethod
    def _enabled_providers() -> list[str]:
        providers_cfg = getattr(settings, 'SOCIALACCOUNT_PROVIDERS', {}) or {}
        if not isinstance(providers_cfg, dict):
            return []
        return sorted(str(key).strip().lower() for key in providers_cfg.keys() if str(key).strip())

    def oauth_clients_view(self, request, company_id: int):
        try:
            company = Company.objects.get(pk=company_id)
        except Company.DoesNotExist as exc:
            raise Http404('Company not found.') from exc
        mappings = list(
            CompanyOAuthClient.objects.filter(company=company)
            .select_related('social_app')
            .order_by('social_app__provider', 'social_app__name', 'id')
        )
        by_provider: dict[str, list[CompanyOAuthClient]] = {}
        for row in mappings:
            provider = str(row.social_app.provider or '').strip().lower()
            by_provider.setdefault(provider, []).append(row)
        provider_rows: list[dict] = []
        for provider in self._enabled_providers():
            rows = by_provider.get(provider, [])
            provider_rows.append(
                {
                    'provider': provider,
                    'enabled': bool(rows),
                    'rows': rows,
                    'add_url': reverse(
                        'admin:companies_company_oauth_client_add_for_provider',
                        args=[company.pk, provider],
                    ),
                }
            )
        context = {
            **self.admin_site.each_context(request),
            'opts': self.model._meta,
            'company': company,
            'title': f'OAuth clients for {company.name}',
            'provider_rows': provider_rows,
        }
        return TemplateResponse(request, 'admin/companies/company/oauth_clients.html', context)

    def oauth_client_add_for_provider_view(self, request, company_id: int, provider: str):
        try:
            company = Company.objects.get(pk=company_id)
        except Company.DoesNotExist as exc:
            raise Http404('Company not found.') from exc
        normalized_provider = str(provider or '').strip().lower()
        if normalized_provider not in self._enabled_providers():
            messages.error(request, f"Provider '{normalized_provider}' is not enabled in settings.")
            return HttpResponseRedirect(reverse('admin:companies_company_oauth_clients', args=[company.pk]))
        add_url = reverse('admin:socialaccount_socialapp_add')
        next_url = reverse('admin:companies_company_oauth_clients', args=[company.pk])
        redirect_to = f'{add_url}?provider={normalized_provider}&_popup=0&next={next_url}'
        return HttpResponseRedirect(redirect_to)


@admin.register(CompanyGroup)
class CompanyGroupAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'company_id')
    search_fields = ('name', 'company__name')
    list_filter = ('company',)
    filter_horizontal = ('members',)


@admin.register(CompanyOAuthClient)
class CompanyOAuthClientAdmin(admin.ModelAdmin):
    list_display = ('id', 'company', 'provider', 'social_app', 'is_active', 'created_at')
    list_filter = ('social_app__provider', 'is_active', 'company')
    search_fields = ('social_app__name', 'social_app__client_id', 'company__name')
    autocomplete_fields = ('company',)
    raw_id_fields = ('social_app',)

    @admin.display(ordering='social_app__provider')
    def provider(self, obj: CompanyOAuthClient) -> str:
        return obj.social_app.provider
