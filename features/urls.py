from django.urls import path
from features import views

urlpatterns = [
    path('', views.FeaturePageView.as_view(), name='features')
]
