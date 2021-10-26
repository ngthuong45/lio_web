from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin


class AccountView(LoginRequiredMixin, TemplateView):
    template_name = 'pages/settings/account.html'


class ConnectionsView(LoginRequiredMixin, TemplateView):
    template_name = 'pages/settings/connections.html'


class BillingView(LoginRequiredMixin, TemplateView):
    template_name = 'pages/settings/billing.html'
