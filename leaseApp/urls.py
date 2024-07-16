from django.urls import path

# Add all your views here
from .views import *

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', login, name='login'),
    path('verify-email/', verify_email, name='verify_email'),
    path('profile/', profile, name='profile'),
    path('password-reset/', password_reset, name='password_reset'),
    path('password-reset-confirm/', password_reset_confirm, name='password_reset_confirm'),
    path('enable-2fa/', enable_2fa, name='enable_2fa'),
    path('disable-2fa/', disable_2fa, name='disable_2fa'),
    # properties urls
    path('properties/', properties, name='properties'),
    path('properties/<int:property_id>/', property_details, name='property_details'),
    # Unit urls
    path('api/units/', manage_units, name='manage_units'),
    path('api/units/<str:property_name>/', manage_units, name='manage_units_property'),
    path('api/units/<str:property_name>/<int:unit_id>/', manage_units, name='manage_units_property_unit'),
    path('api/units/<int:unit_id>/', manage_units, name='manage_units_unit'),
    # Unit Management
    path('api/units/', manage_units, name='manage_units'),
    path('api/units/<int:unit_id>/', manage_units, name='unit_detail'),

    # Lease Management
    path('api/leases/', manage_leases, name='manage_lease'),
    path('api/leases/<int:lease_id>/', manage_leases, name='lease_detail'),

    # Rent Management
    path('api/rentpayments/', manage_rentpayments, name='manage_rentpayments'),
    path('api/rentpayments/<int:payment_id>/', manage_rentpayments, name='rentpayment_detail'),

    # Maintenance Management
    path('api/maintenancerequests/', manage_maintenancerequests, name='manage_maintenancerequests'),
    path('api/maintenancerequests/<int:request_id>/', manage_maintenancerequests, name='maintenancerequest_detail'),

    # Communication Management
    path('api/messages/', manage_messages, name='manage_messages'),
    path('api/messages/<int:message_id>/', manage_messages, name='message_detail'),

    # Document Management
    path('api/documents/', manage_documents, name='manage_documents'),
    path('api/documents/<int:document_id>/', manage_documents, name='document_detail'),

    # Financial Management - Expenses
    path('api/expenses/', manage_expenses, name='manage_expenses'),
    path('api/expenses/<int:expense_id>/', manage_expenses, name='expense_detail'),

    # Feedback Management
    path('api/feedback/', manage_feedback, name='manage_feedback'),
    path('api/feedback/<int:feedback_id>/', manage_feedback, name='feedback_detail'),

    # Forum Management
    path('api/forums/', manage_forums, name='manage_forums'),
    path('api/forums/<int:forum_id>/', manage_forums, name='forum_detail'),

    # Forum Messages Management
    path('api/forummessages/', manage_forum_messages, name='manage_forummessages'),
    path('api/forummessages/<int:forummessage_id>/', manage_forum_messages, name='forummessage_detail'),
]

