from django.urls import path

# Add all your views here
from .views import *

urlpatterns = [
    path('status/', status_view, name='status'),
    # Register user urls
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
    path('units/', manage_units, name='manage_units'),
    path('units/<int:property_id>/', manage_units, name='manage_units_by_property'),
    path('units/<int:property_id>/<int:unit_id>/', manage_units, name='manage_unit_detail'),
    # URLs for managing Lease objects
    path('leases/', manage_leases, name='manage_leases'),
    path('leases/<int:lease_id>/', manage_leases, name='manage_lease'),

    # URLs for managing RentPayment objects
    path('rent-payments/', manage_rentpayments, name='manage_rentpayments'),
    path('rent-payments/<int:payment_id>/', manage_rentpayments, name='manage_rentpayment'),

    # URLs for managing MaintenanceRequest objects
    path('maintenance-requests/', manage_maintenancerequests, name='manage_maintenancerequests'),
    path('maintenance-requests/<int:request_id>/', manage_maintenancerequests, name='manage_maintenancerequest'),

    # URLs for managing Message objects
    path('messages/', manage_messages, name='manage_messages'),
    path('messages/<int:message_id>/', manage_messages, name='manage_message'),

    # URLs for managing Document objects
    path('documents/', manage_documents, name='manage_documents'),
    path('documents/<int:document_id>/', manage_documents, name='manage_document'),

    # URLs for managing Expense objects
    path('expenses/', manage_expenses, name='manage_expenses'),
    path('expenses/<int:expense_id>/', manage_expenses, name='manage_expense'),

    # URLs for managing Feedback objects
    path('feedback/', manage_feedback, name='manage_feedback'),
    path('feedback/<int:feedback_id>/', manage_feedback, name='manage_feedback_detail'),

    # URLs for managing Vendor objects
    path('vendors/', manage_vendors, name='manage_vendors'),
    path('vendors/<int:vendor_id>/', manage_vendors, name='manage_vendor'),

    # URLs for managing TenantScreening objects
    path('tenant-screening/', manage_tenant_screening, name='manage_tenant_screening'),
    path('tenant-screening/<int:screening_id>/', manage_tenant_screening, name='manage_tenant_screening_detail'),

    # URLs for managing Forum objects
    path('forums/', manage_forum, name='manage_forum'),
    path('forums/<int:forum_id>/', manage_forum, name='manage_forum_detail'),

    # URLs for managing ForumMessage objects
    path('forums/<int:forum_id>/messages/', manage_forum_messages, name='manage_forum_messages'),
    path('forums/<int:forum_id>/messages/<int:message_id>/', manage_forum_messages, name='manage_forum_message'),
]

