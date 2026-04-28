from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0004_companyoauthredirect'),
    ]

    operations = [
        migrations.CreateModel(
            name='CompanyOAuthClient',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'provider',
                    models.CharField(
                        choices=[('github', 'GitHub'), ('google', 'Google'), ('microsoft', 'Microsoft')],
                        max_length=32,
                    ),
                ),
                ('label', models.CharField(max_length=150)),
                ('client_id', models.CharField(max_length=255)),
                ('client_secret', models.CharField(max_length=255)),
                ('tenant', models.CharField(blank=True, max_length=255)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'company',
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name='oauth_clients',
                        to='companies.company',
                    ),
                ),
            ],
            options={
                'ordering': ['provider', 'label', 'id'],
            },
        ),
        migrations.AddConstraint(
            model_name='companyoauthclient',
            constraint=models.UniqueConstraint(
                fields=('company', 'provider', 'label'),
                name='company_oauth_client_unique_label_per_provider',
            ),
        ),
        migrations.AddConstraint(
            model_name='companyoauthclient',
            constraint=models.UniqueConstraint(
                fields=('company', 'provider', 'client_id'),
                name='company_oauth_client_unique_client_id_per_provider',
            ),
        ),
    ]
