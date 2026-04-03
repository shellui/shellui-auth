from rest_framework import serializers


class ProviderAuthorizeSerializer(serializers.Serializer):
    redirect_uri = serializers.URLField()


class ProviderCallbackSerializer(serializers.Serializer):
    code = serializers.CharField()
    redirect_uri = serializers.URLField()


class UserPreferenceSerializer(serializers.Serializer):
    themeName = serializers.CharField(required=False, allow_blank=False, max_length=100)
    language = serializers.ChoiceField(required=False, choices=['en', 'fr'])
    region = serializers.CharField(required=False, allow_blank=False, max_length=64)
    colorScheme = serializers.ChoiceField(required=False, choices=['light', 'dark', 'system'])


class ShellUIAdminUserUpdateSerializer(serializers.Serializer):
    """Partial update for Django user fields plus optional ShellUI user_metadata merge (`data`)."""

    first_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    last_name = serializers.CharField(required=False, allow_blank=True, max_length=150)
    is_staff = serializers.BooleanField(required=False)
    is_active = serializers.BooleanField(required=False)
    data = serializers.JSONField(required=False)
    group_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        required=False,
        allow_empty=True,
    )


class ShellUIAdminGroupCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=150)


class ShellUIAdminGroupUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=150)
