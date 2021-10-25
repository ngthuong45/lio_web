from django.urls import path
from pages import views

urlpatterns = [
    path('', views.HomePageView.as_view(), name='homepage'),
    path('user-account/', views.AccountView.as_view(), name='user-account'),
    path('user-account/connections.html', views.ConnectionsView.as_view(), name='user-account-connections'),
    path('user-account/billing.html', views.BillingView.as_view(), name='user-account-billing'),
]
