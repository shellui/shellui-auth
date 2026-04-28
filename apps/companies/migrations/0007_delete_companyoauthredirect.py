from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('companies', '0006_companyoauthclient_use_socialapp'),
    ]

    operations = [
        migrations.DeleteModel(
            name='CompanyOAuthRedirect',
        ),
    ]
