from django.contrib import admin

from .models import Company, CompanyGroup, CompanyOAuthRedirect


class CompanyOAuthRedirectInline(admin.TabularInline):
    model = CompanyOAuthRedirect
    extra = 1
    fields = ('base_url', 'label', 'is_active', 'created_at')
    readonly_fields = ('created_at',)


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'slug')
    search_fields = ('name', 'slug')
    filter_horizontal = ('members', 'owners')
    inlines = [CompanyOAuthRedirectInline]


@admin.register(CompanyGroup)
class CompanyGroupAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'company_id')
    search_fields = ('name', 'company__name')
    list_filter = ('company',)
    filter_horizontal = ('members',)


@admin.register(CompanyOAuthRedirect)
class CompanyOAuthRedirectAdmin(admin.ModelAdmin):
    list_display = ('id', 'company', 'base_url', 'label', 'is_active', 'created_at')
    list_filter = ('is_active', 'company')
    search_fields = ('base_url', 'label', 'company__name')
    autocomplete_fields = ('company',)
