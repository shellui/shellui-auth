from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('companies', '0002_company_owners'),
        ('authapi', '0004_user_activity'),
    ]

    operations = [
        migrations.AddField(
            model_name='loginevent',
            name='company',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.deletion.SET_NULL,
                related_name='login_events',
                to='companies.company',
            ),
        ),
    ]
