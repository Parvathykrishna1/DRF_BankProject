# Generated by Django 5.0.4 on 2024-05-10 07:19

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('staffportal', '0003_remove_loanapproval_loan_application_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='loanapproval',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
