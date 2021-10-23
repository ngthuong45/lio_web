from django.db import models


class ZaloWebhook(models.Model):
    object = models.CharField(max_length=255)
    object_id = models.CharField(max_length=255)
    received_at = models.DateTimeField(help_text='When we received the event.')
    payload = models.JSONField(default=None, null=True)

    class Meta:
        indexes = [
            models.Index(fields=['received_at']),
        ]
