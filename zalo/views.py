import datetime
import json
from secrets import compare_digest

from django.conf import settings
from django.db.transaction import atomic, non_atomic_requests
from django.http import HttpResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import hashlib
import hmac
from django.utils import timezone
from django.views import generic
from django.utils.decorators import method_decorator

from zalo.models import ZaloWebhook
# using time module
import time

ZALO = {
    'app_id': '840285093686170967',
    'oa_secret_key': 'vMFg2fLnlfd5Ltt0GkyC'
}


@csrf_exempt
@require_POST
@non_atomic_requests
def zalo_webhook(request):
    """
    Mock data:
        {
          "app_id": "840285093686170967",
          "user_id_by_app": "6280932764005168453",
          "event_name": "user_send_text",
          "timestamp": "1634909662710",
          "sender": {
            "id": "7283505279911446385"
          },
          "recipient": {
            "id": "579745863508352884"
          },
          "message": {
            "msg_id": "This is message id",
            "text": "This is testing message"
          }
        }
    """
    header_signature = request.headers.get('X-Zevent-Signature', None)
    if header_signature is None:
        return HttpResponseForbidden(
            'X-Zevent-Signature: None (403)',
            content_type='text/plain',
        )

    sha_name, signature = header_signature.split('=')
    if sha_name != 'mac':
        return HttpResponseForbidden(
            "X-Zevent-Signature: not 'mac' (403)",
            content_type='text/plain',
        )

    payload = json.loads(request.body)
    sig_string = '{app_id}{data}{timestamp}{oasecretKey}'.format(
        app_id=ZALO['app_id'],
        data=payload,
        timestamp=payload['timestamp'],
        oasecretKey=ZALO['oa_secret_key']
    )
    # mac = sha256(appId + data + timeStamp + OAsecretKey)
    result = hashlib.sha256(sig_string.encode()).hexdigest()










    # Check the X-Hub-Signature header to make sure this is a valid request.
    # expected_signature = hmac.new(
    #     ZALO['app_id'].encode('utf-8'), sig_basestring.encode('utf-8'), hashlib.sha256
    # ).hexdigest()

    print('local: ', result)
    print('server: ', signature)

    if not hmac.compare_digest(signature, result):
        print("here")

    # print(payload)

    # given_token = request.headers.get("Acme-Webhook-Token", "")
    # if not compare_digest(given_token, settings.ACME_WEBHOOK_TOKEN):
    #     return HttpResponseForbidden(
    #         "Incorrect token in Acme-Webhook-Token header.",
    #         content_type="text/plain",
    #     )
    #
    # ZaloWebhook.objects.filter(
    #     received_at__lte=timezone.now() - datetime.timedelta(days=7)
    # ).delete()
    # payload = json.loads(request.body)
    # ZaloWebhook.objects.create(
    #     received_at=timezone.now(),
    #     payload=payload,
    # )

    # print(json.loads(request.body))

    return HttpResponse('Message received okay!', content_type="text/plain")
