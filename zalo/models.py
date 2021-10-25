from django.db import models
from accounts.models import User

class ZaloWebhook(models.Model):
    event_name = models.CharField(max_length=255)
    received_at = models.DateTimeField(help_text='When we received the event.')
    payload = models.JSONField(default=None, null=True)

    class Meta:
        indexes = [
            models.Index(fields=['received_at']),
        ]


class ZaloOA(models.Model):
    oa_id = models.CharField(max_length=255)
    name = models.CharField(max_length=255, blank=True)
    avatar = models.URLField(blank=True)
    is_verified = models.BooleanField(default=False)
    access_token = models.TextField()
    refresh_token = models.TextField()
    expires_in = models.TextField()

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='zalo_oa')

    def __str__(self):
        return self.name
