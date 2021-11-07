from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin


class FeaturePageView(LoginRequiredMixin, TemplateView):
    template_name = 'pages/feature.html'
