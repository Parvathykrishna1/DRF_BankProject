# Generated by Django 5.0.4 on 2024-05-08 07:50

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('staffportal', '0002_customuser_failed_login_attempts_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='failed_login_attempts',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='is_blocked',
        ),
    ]