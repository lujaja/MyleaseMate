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
    add_property,
    list_properties,
    property_details,
    update_property,
    delete_property,
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
    path('properties/', add_property, name='add_property'),
    path('properties/', list_properties, name='list_properties'),
    path('properties/<int:property_id>/', property_details, name='property_details'),
    path('properties/<int:property_id>/', update_property, name='update_property'),
    path('properties/<int:property_id>/', delete_property, name='delete_property'),
]

