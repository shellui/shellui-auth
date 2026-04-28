import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('companies', '0003_companygroup'),
    ]

    operations = [
        migrations.CreateModel(
            name='CompanyOAuthRedirect',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('base_url', models.CharField(max_length=500)),
                ('label', models.CharField(blank=True, max_length=150)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                (
                    'company',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='oauth_redirect_allowlist',
                        to='companies.company',
                    ),
                ),
            ],
            options={
                'ordering': ['id'],
            },
        ),
        migrations.AddConstraint(
            model_name='companyoauthredirect',
            constraint=models.UniqueConstraint(
                fields=('company', 'base_url'),
                name='company_oauth_redirect_unique_base_per_company',
            ),
        ),
    ]
