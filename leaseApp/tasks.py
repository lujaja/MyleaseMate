from celery import shared_task
from django.core.mail import send_mail
from .models import Property
import logging

logger = logging.getLogger(__name__)

@shared_task
def send_verification_email(email, code):
    try:
        send_mail(
            'Email Verification',
            f'Your verification code is {code}',
            'noreply@myleasemate.com',
            [email],
            fail_silently=False,
        )
        logger.info(f'Email verification sent to {email}')
    except Exception as e:
        logger.error(f'Failed to send verification email to {email}: {e}')

@shared_task
def send_password_reset_email(email, code):
    try:
        send_mail(
            'Password Reset',
            f'Your password reset code is {code}',
            'noreply@myleasemate.com',
            [email],
            fail_silently=False,
        )
        logger.info(f'Password reset email sent to {email}')
    except Exception as e:
        logger.error(f'Failed to send password reset email to {email}: {e}')

@shared_task
def update_property_valuation(property_id, new_valuation):
    try:
        property = Property.objects.get(id=property_id)
        property.valuation = new_valuation
        property.save()
        logger.info(f'Property valuation updated: Property ID {property_id}')
    except Property.DoesNotExist:
        logger.error(f'Property with ID {property_id} does not exist')
    except Exception as e:
        logger.error(f'Failed to update property valuation for Property ID {property_id}: {e}')