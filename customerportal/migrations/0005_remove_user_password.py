# Generated by Django 5.0.4 on 2024-05-08 09:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('customerportal', '0004_remove_user_username'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='password',
        ),
    ]