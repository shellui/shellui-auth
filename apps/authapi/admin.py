from django.contrib import admin

from .models import LoginEvent, UserActivity, UserPreference


@admin.register(LoginEvent)
class LoginEventAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'created_at',
        'outcome',
        'provider',
        'user',
        'is_staff_at_event',
        'client_country',
        'client_city',
    )
    list_filter = ('outcome', 'provider', 'is_staff_at_event')
    search_fields = ('user__email', 'user__username', 'ip_hash', 'failure_reason')
    ordering = ('-created_at', '-id')
    readonly_fields = (
        'created_at',
        'user',
        'outcome',
        'provider',
        'failure_reason',
        'is_staff_at_event',
        'ip_hash',
        'user_agent',
        'client_timezone',
        'client_device_id_hash',
        'client_country',
        'client_city',
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ('user', 'last_seen_at')
    ordering = ('-last_seen_at',)
    search_fields = ('user__email', 'user__username')
    readonly_fields = ('user', 'last_seen_at')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(UserPreference)
class UserPreferenceAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'user',
        'language',
        'color_scheme',
        'theme_name',
        'region',
        'updated_at',
    )
    list_select_related = ('user',)
    list_filter = ('language', 'color_scheme')
    search_fields = ('user__username', 'user__email', 'theme_name', 'region')
    ordering = ('user_id',)
    readonly_fields = ('created_at', 'updated_at')
