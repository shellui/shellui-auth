from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Company
from .serializers import CompanySerializer, CompanyUpdateSerializer


@extend_schema_view(
    list=extend_schema(
        tags=['companies'],
        summary='List user companies',
        description='Return companies where the authenticated user is a member.',
    ),
    retrieve=extend_schema(
        tags=['companies'],
        summary='Get company details',
        description='Return company details only if the authenticated user is a member.',
    ),
    partial_update=extend_schema(
        tags=['companies'],
        summary='Update company settings',
        description='Only company owners can update company name and owners list.',
        request=CompanyUpdateSerializer,
    ),
    update=extend_schema(
        tags=['companies'],
        summary='Replace company settings',
        description='Only company owners can update company name and owners list.',
        request=CompanyUpdateSerializer,
    ),
)
class CompanyViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'slug'
    queryset = Company.objects.none()

    def get_queryset(self):
        return Company.objects.filter(members=self.request.user)

    def partial_update(self, request, *args, **kwargs):
        company = self.get_object()
        if not company.owners.filter(pk=request.user.pk).exists():
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        serializer = CompanyUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        if 'name' in validated:
            company.name = validated['name']
            company.save(update_fields=['name'])

        if 'owner_ids' in validated:
            owner_ids = validated['owner_ids']
            members_qs = company.members.filter(pk__in=owner_ids)
            if members_qs.count() != len(set(owner_ids)):
                return Response(
                    {'error': 'All owners must be members of this company.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            company.owners.set(members_qs)

        return Response(CompanySerializer(company).data)
