# Generated by Django 5.1.4 on 2024-12-07 13:55

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0004_keys_paid_status_keys_unique_token'),
    ]

    operations = [
        migrations.RenameField(
            model_name='keys',
            old_name='unique_token',
            new_name='unique_email_token',
        ),
    ]
