from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('companies', '0002_company_owners'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='CompanyGroup',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=150)),
                (
                    'company',
                    models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='groups', to='companies.company'),
                ),
                (
                    'members',
                    models.ManyToManyField(blank=True, related_name='company_groups', to=settings.AUTH_USER_MODEL),
                ),
            ],
            options={'ordering': ['name']},
        ),
        migrations.AddConstraint(
            model_name='companygroup',
            constraint=models.UniqueConstraint(
                fields=('company', 'name'),
                name='company_group_unique_name_per_company',
            ),
        ),
    ]
