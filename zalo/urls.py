from django.urls import path
from zalo import views

urlpatterns = [
    path('webhook', views.zalo_webhook, name='zalo-webhook'),
]
