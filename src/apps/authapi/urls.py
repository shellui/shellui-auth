from django.urls import path

from .views import (
    ShellUIAdminUserDetailView,
    ShellUIAdminUserListView,
    ShellUIAuthSettingsView,
    ShellUIAuthorizeView,
    ShellUILogoutView,
    ShellUIOAuthCallbackView,
    ShellUIPreferenceView,
    ShellUITokenView,
    ShellUIUserView,
    SocialAuthorizeView,
    SocialLoginView,
)

urlpatterns = [
    path('settings', ShellUIAuthSettingsView.as_view(), name='shellui-settings'),
    path('authorize', ShellUIAuthorizeView.as_view(), name='shellui-authorize'),
    path('oauth/callback', ShellUIOAuthCallbackView.as_view(), name='shellui-oauth-callback'),
    path('token', ShellUITokenView.as_view(), name='shellui-token'),
    path('logout', ShellUILogoutView.as_view(), name='shellui-logout'),
    path('user', ShellUIUserView.as_view(), name='shellui-user'),
    path('admin/users', ShellUIAdminUserListView.as_view(), name='shellui-admin-users'),
    path('admin/users/<int:pk>', ShellUIAdminUserDetailView.as_view(), name='shellui-admin-user-detail'),
    path('preferences', ShellUIPreferenceView.as_view(), name='shellui-preferences'),
    path('providers/<str:provider>/authorize/', SocialAuthorizeView.as_view(), name='social-authorize'),
    path('providers/<str:provider>/login/', SocialLoginView.as_view(), name='social-login'),
]
