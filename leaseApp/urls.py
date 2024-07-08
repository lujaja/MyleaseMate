from django.urls import path

# Add all your views here
from .views import (
    register,
    login,
    verify_email,
    profile,
    password_reset,
    password_reset_confirm,
    enable_2fa,
    disable_2fa,
    properties,
    property_details,
)

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', login, name='login'),
    path('verify-email/', verify_email, name='verify_email'),
    path('profile/', profile, name='profile'),
    path('password-reset/', password_reset, name='password_reset'),
    path('password-reset-confirm/', password_reset_confirm, name='password_reset_confirm'),
    path('enable-2fa/', enable_2fa, name='enable_2fa'),
    path('disable-2fa/', disable_2fa, name='disable_2fa'),
    path('properties/', properties, name='properties'),
    path('properties/<int:property_id>/', property_details, name='property_details'),
]

