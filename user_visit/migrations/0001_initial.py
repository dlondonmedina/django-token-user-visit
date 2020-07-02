# Generated by Django 3.0.8 on 2020-07-02 20:27

import uuid

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="UserVisit",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "timestamp",
                    models.DateTimeField(
                        default=django.utils.timezone.now,
                        help_text=(
                            "The time at which the first visit of the day was recorded"
                        ),
                    ),
                ),
                (
                    "session_key",
                    models.CharField(
                        help_text="Django session identifier", max_length=40
                    ),
                ),
                (
                    "remote_addr",
                    models.CharField(
                        blank=True,
                        help_text=(
                            "Client IP address (from X-Forwarded-For HTTP header, "
                            "or REMOTE_ADDR request property)"
                        ),
                        max_length=100,
                    ),
                ),
                (
                    "ua_string",
                    models.TextField(
                        blank=True,
                        help_text="Client User-Agent HTTP header",
                        verbose_name="User agent (raw)",
                    ),
                ),
                ("uuid", models.UUIDField(default=uuid.uuid4, editable=False)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="user_visits",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
