# Generated by Django 5.0.4 on 2024-05-10 06:06

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('customerportal', '0004_fundtransfer_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='expense',
            name='category',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='customerportal.budget'),
        ),
    ]
