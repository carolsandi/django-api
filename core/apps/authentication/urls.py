from django.urls import path
from rest_framework_simplejwt import views as jwt_views

from .views import (
    LoginAPIView, RegistrationAPIView, UserRetrieveUpdateAPIView
)

urlpatterns = [
    path('register', RegistrationAPIView.as_view(), name='register'),
    path('login', LoginAPIView.as_view(), name='login'),
    path('users', UserRetrieveUpdateAPIView.as_view(), name='users'),
    path('login/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('logout', jwt_views.TokenBlacklistView.as_view(), name='token_blacklist'),
]
