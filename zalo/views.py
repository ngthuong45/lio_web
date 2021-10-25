import datetime
import json
import hashlib
import hmac
import base64
import secrets
import requests

from django.db.transaction import non_atomic_requests
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone
from django.views import generic
from django.contrib.auth.mixins import LoginRequiredMixin

from core.settings import ZALO_APP_ID, ZALO_OA_SECRET_KEY, ZALO_APP_KEY, BASE_URL
from zalo.models import ZaloWebhook, ZaloOA
from accounts.models import User


@csrf_exempt
@require_POST
@non_atomic_requests
def zalo_webhook(request):
    """
    mock_data:
        {
            "app_id": "840285093686170967",
            "sender": {
                "id": "2651040744560330253"
            },
            "message": {
                "text": "Y",
                "msg_id": "1d19cfb48434f168a827"
            },
            "recipient": {
                "id": "1945001651380238465"
            },
            "timestamp": "1635041570508",
            "event_name": "user_send_text",
            "reorder_id": "1635041570508",
            "user_id_by_app": "6280932764005168453"
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

    if 'timestamp' in payload:
        # mac = sha256(appId + data + timeStamp + OAsecretKey)
        sig_string = ZALO_APP_ID.encode() + request.body + payload['timestamp'].encode() + ZALO_OA_SECRET_KEY.encode()
        expected_signature = hashlib.sha256(sig_string).hexdigest()

        # Check the X-Zevent-Signature header to make sure this is a valid request.
        if not hmac.compare_digest(signature, expected_signature):
            return HttpResponseForbidden(
                'Incorrect X-Zevent-Signature in header.',
                content_type='text/plain',
            )

        ZaloWebhook.objects.filter(
            received_at__lte=timezone.now() - datetime.timedelta(days=7)
        ).delete()

        ZaloWebhook.objects.create(
            event_name=payload['event_name'],
            received_at=timezone.now(),
            payload=payload,
        )

    return HttpResponse('Message received okay!', content_type='text/plain')


class ZaloOa(LoginRequiredMixin, generic.View):

    @staticmethod
    def get_info_oa(access_token):
        url = 'https://openapi.zalo.me/v2.0/oa/getoa'
        headers = {'access_token': access_token}

        result = requests.get(url=url, headers=headers).json()

        if result['error'] == 0 and 'data' in result:
            return result['data']

        return HttpResponse(f"Zalo get information OA error: {result['message']}",
                            content_type='text/plain',
                            status=400)

    def get_access_token(self, user_id, code_verifier, zalo_auth_code):
        """
        response:
                {
                    'access_token': 'CXZLTlwbfJOo4zvrzggdDpeSsNS',
                    'refresh_token': 'vZ45FLsfdsf11dasda111198BVFfEhMe',
                    'expires_in': '3600'
                }
        """
        url = 'https://oauth.zaloapp.com/v4/oa/access_token'
        headers = {'secret_key': ZALO_APP_KEY}
        data = {
            'code': zalo_auth_code,
            'app_id': ZALO_APP_ID,
            'grant_type': 'authorization_code',
            'code_verifier': code_verifier
        }

        result = requests.post(url=url, headers=headers, data=data).json()
        info_oa = self.get_info_oa(access_token=result['access_token'])

        ZaloOA.objects.create(
            oa_id=str(info_oa['oa_id']),
            name=info_oa['name'],
            avatar=info_oa['avatar'],
            is_verified=info_oa['is_verified'],
            access_token=result['access_token'],
            refresh_token=result['refresh_token'],
            expires_in=result['expires_in'],
            user_id=user_id
        )

    def post(self, request, *args, **kwargs):
        try:
            user = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return HttpResponse('Not found user.', content_type='text/plain', status=400)

        code_verifier = secrets.token_urlsafe(96)[:43]  # code_verifier must '43 <= len(code_verifier) <= 128'

        user.secret_key = code_verifier
        user.save(update_fields=['secret_key'])

        # code challenge PKCE
        hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
        encoded = base64.urlsafe_b64encode(hashed)
        code_challenge = encoded.decode('ascii')[:-1]

        url_callback = f"{BASE_URL}/zalo/oa-auth/"
        url_oa_auth = f"https://oauth.zaloapp.com/v4/oa/permission?" \
                      f"app_id={ZALO_APP_ID}" \
                      f"&redirect_uri={url_callback}" \
                      f"&code_challenge={code_challenge}"

        return HttpResponseRedirect(url_oa_auth)

    def get(self, request, *args, **kwargs):
        user_id = request.user.id
        zalo_auth_code = self.request.GET.get('code')
        zalo_oa_id = self.request.GET.get('oa_id')
        zalo_code_challenge = self.request.GET.get('code_challenge')

        if (zalo_oa_id is None
                or zalo_code_challenge is None
                or zalo_auth_code is None):
            return HttpResponse('Not found code/oa_id/code_challenge', content_type='text/plain', status=400)

        try:
            user = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return HttpResponse('Not found user.', content_type='text/plain', status=400)

        code_verifier = user.secret_key
        hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
        encoded = base64.urlsafe_b64encode(hashed)
        user_code_challenge = encoded.decode('ascii')[:-1]

        if zalo_code_challenge != user_code_challenge:
            return HttpResponse('Incorrect code challenge.', content_type='text/plain', status=400)

        if ZaloOA.objects.filter(oa_id=zalo_oa_id, user_id=user_id):
            return HttpResponse('oa_id is exist', content_type='text/plain')

        self.get_access_token(user_id, code_verifier, zalo_auth_code)

        return HttpResponse('okay!', content_type='text/plain')
