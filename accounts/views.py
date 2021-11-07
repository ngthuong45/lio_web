from django.views.generic import TemplateView, View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render

from zalo.models import ZaloOA


class AccountView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        zalo_oa = ZaloOA.objects.filter(user_id=request.user.id)
        return render(request, 'pages/settings/user/account.html', {'zalo_oa': zalo_oa})


class ConnectionsView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        message_alert = f"Tài khoản Zalo OA - kết nối thành công!"
        return render(request, 'pages/settings/user/connections.html', {'success_alert': message_alert})


class BillingView(LoginRequiredMixin, TemplateView):
    template_name = 'pages/settings/user/billing.html'
