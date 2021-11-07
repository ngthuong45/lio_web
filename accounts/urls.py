from django.urls import path
from accounts import views

urlpatterns = [
    path('', views.AccountView.as_view(), name='user-account'),
    path('connections.html', views.ConnectionsView.as_view(), name='user-account-connections'),
    path('billing.html', views.BillingView.as_view(), name='user-account-billing'),
]
