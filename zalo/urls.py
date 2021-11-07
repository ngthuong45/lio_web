from django.urls import path
from zalo import views
from core.settings import ZALO_URL_SECRET_KEY

urlpatterns = [
    path(f'webhook/{ZALO_URL_SECRET_KEY}', views.zalo_webhook, name='zalo-webhook'),
    path('oa-auth/', views.ZaloOa.as_view(), name='zalo-oa-auth'),
]
