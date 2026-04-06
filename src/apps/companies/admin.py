from django.contrib import admin

from .models import Company, CompanyGroup


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'slug')
    search_fields = ('name', 'slug')
    filter_horizontal = ('members', 'owners')


@admin.register(CompanyGroup)
class CompanyGroupAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'company_id')
    search_fields = ('name', 'company__name')
    list_filter = ('company',)
    filter_horizontal = ('members',)
