# Generated by Django 5.1.6 on 2025-02-15 17:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('business', '0003_user_otp_created_at'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='otp_created_at',
        ),
    ]
