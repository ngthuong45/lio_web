# Generated by Django 3.2.8 on 2021-11-07 06:36

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ZaloOA',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('oa_id', models.CharField(max_length=255)),
                ('name', models.CharField(blank=True, max_length=255)),
                ('avatar', models.URLField(blank=True)),
                ('is_verified', models.BooleanField(default=False)),
                ('access_token', models.TextField()),
                ('refresh_token', models.TextField()),
                ('expires_in', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='ZaloWebhook',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_name', models.CharField(max_length=255)),
                ('received_at', models.DateTimeField(help_text='When we received the event.')),
                ('payload', models.JSONField(default=None, null=True)),
            ],
        ),
        migrations.AddIndex(
            model_name='zalowebhook',
            index=models.Index(fields=['received_at'], name='zalo_zalowe_receive_4a1e4a_idx'),
        ),
        migrations.AddField(
            model_name='zalooa',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='zalo_oa', to=settings.AUTH_USER_MODEL),
        ),
    ]
