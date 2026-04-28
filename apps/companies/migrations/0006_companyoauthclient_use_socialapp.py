from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0005_companyoauthclient'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='companyoauthclient',
            name='company_oauth_client_unique_label_per_provider',
        ),
        migrations.RemoveConstraint(
            model_name='companyoauthclient',
            name='company_oauth_client_unique_client_id_per_provider',
        ),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='client_id',
        ),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='client_secret',
        ),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='label',
        ),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='provider',
        ),
        migrations.RemoveField(
            model_name='companyoauthclient',
            name='tenant',
        ),
        migrations.AddField(
            model_name='companyoauthclient',
            name='social_app',
            field=models.ForeignKey(
                default=1,
                on_delete=models.deletion.CASCADE,
                related_name='company_oauth_clients',
                to='socialaccount.socialapp',
            ),
            preserve_default=False,
        ),
        migrations.AddConstraint(
            model_name='companyoauthclient',
            constraint=models.UniqueConstraint(
                fields=('company', 'social_app'),
                name='company_oauth_client_unique_social_app_per_company',
            ),
        ),
    ]
