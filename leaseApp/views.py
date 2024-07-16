# Imports
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.utils.crypto import get_random_string
from .models import *
from .tasks import (
    update_property_valuation,
    process_unit_request
)

# import Serializers here after adding them in the named file
from .serializers import *

# import all tasks allocated to celery here
from .tasks import (
    send_verification_email,
    send_password_reset_email
)

User = get_user_model()
"""
********************************************************
* User Manager APIs                                    *
********************************************************
"""
# Register user Endpoint
# tested and working
@api_view(['POST'])
def register(request):
    serializer = UserRegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        code = get_random_string(length=6, allowed_chars='0123456789')
        user.verification_code = code
        user.save()
        send_verification_email.delay(user.email, code)
        return Response({'detail': 'User account created successfully. Verification email sent.'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Login Endpoint
# Test and working
@api_view(['POST'])
def login(request):
    print(request.data)
    serializer = UserLoginSerializer(data=request.data, context={'request': request})
    
    if serializer.is_valid():
        user = serializer.validated_data['user']
        print(user)
        
        # Check if two-factor authentication is enabled for the user
        if user.two_factor_auth:
            if 'otp_token' not in request.data:
                return Response({'detail': 'OTP token required'}, status=status.HTTP_400_BAD_REQUEST)
            
            device = TOTPDevice.objects.get(user=user, name='default')
            if not device.verify_token(request.data.get('otp_token')):
                return Response({'detail': 'Invalid OTP token'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        tokens = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        
        # Send verification code via email if 2FA is enabled
        if user.two_factor_auth:
            verification_code = get_random_string(length=6, allowed_chars='0123456789')
            print(f'verification code {verification_code} sent to {user.email}')
            send_verification_email.delay(user.email, verification_code)
        
        return Response(tokens, status=status.HTTP_200_OK)
    print(serializer.errors)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# email verification after account creation
# Tested and not sending email
@api_view(['POST'])
def verify_email(request):
    serializer = EmailVerificationSerializer(data=request.data)
    if serializer.is_valid():
        try:
            user = User.objects.get(email=serializer.validated_data['email'])
            if user.verification_code == serializer.validated_data['code']:
                user.isActive = True
                user.verification_code = ''  # Clear verification code after successful verification
                user.save()
                return Response({'detail': 'Email verified successfully'}, status=status.HTTP_200_OK)
            return Response({'detail': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# profile Endpoint that allows the user to either update or view his profile
# tested and working
@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def profile(request):
    if request.method == 'GET':
        serializer = UserProfileSerializer(request.user)
        print(f'Received get request -> {request.data}')
        return Response(serializer.data, status=status.HTTP_200_OK)
    elif request.method == 'PUT':
        print(f'Received put request -> {request.data}')
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# This Endpoint Allows the user to reset password
# tested and not sending mail
@api_view(['POST'])
def password_reset(request):
    serializer = PasswordResetSerializer(data=request.data)
    print(f'Receaved password reset request-> {request.data}')
    if serializer.is_valid():
        try:
            user = User.objects.get(email=serializer.validated_data['email'])
            code = get_random_string(length=6, allowed_chars='0123456789')
            user.verification_code = code
            user.save()
            send_password_reset_email.delay(user.email, code)
            return Response({'detail': 'Password reset code sent to email'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# This Endpoint Confirms password reset
# Tested and not sending mail
@api_view(['POST'])
def password_reset_confirm(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    if serializer.is_valid():
        try:
            user = User.objects.get(email=serializer.validated_data['email'])
            if user.verification_code == serializer.validated_data['code']:
                user.set_password(serializer.validated_data['new_password'])
                user.verification_code = ''
                user.save()
                return Response({'detail': 'Password reset successful'}, status=status.HTTP_200_OK)
            return Response({'detail': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# This Endpoint Allows the User to set 2fa to improve account security
# tested and working correctly
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def enable_2fa(request):
    user = request.user
    device, created = TOTPDevice.objects.get_or_create(user=user, name='default')
    if created or not device.confirmed:
        device.confirmed = True
        device.save()
        user.twoFactorAuth = True
        user.save()
        return Response({'detail': '2FA enabled successfully'}, status=status.HTTP_200_OK)
    return Response({'detail': '2FA already enabled'}, status=status.HTTP_400_BAD_REQUEST)

# This Endpoint Allows the user to Disable 2fa on his account
# Tested and working fine
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable_2fa(request):
    user = request.user
    TOTPDevice.objects.filter(user=user, name='default').delete()
    user.twoFactorAuth = False
    user.save()
    return Response({'detail': '2FA disabled successfully'}, status=status.HTTP_200_OK)

"""
********************************************************
* Property APIs                                    *
********************************************************
"""

@api_view(['POST', 'GET'])
@permission_classes([IsAuthenticated])
def properties(request):
    if request.user.role != 'Landlord':
        return Response({'detail': 'Only landlords can manage properties'}, status=status.HTTP_403_FORBIDDEN)
    
    if request.method == 'POST':
        serializer = PropertySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    if request.method == 'GET':
        properties = Property.objects.filter(user=request.user)
        serializer = PropertySerializer(properties, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def property_details(request, property_id):
    try:
        property = Property.objects.get(id=property_id, user=request.user)
    except Property.DoesNotExist:
        return Response({'detail': 'Property not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = PropertySerializer(property)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    if request.method == 'PUT':
        serializer = PropertySerializer(property, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()

            # Example: Call Celery task asynchronously
            new_valuation = serializer.validated_data.get('valuation')
            if new_valuation:
                update_property_valuation.delay(property.id, new_valuation)

            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    if request.method == 'DELETE':
        property.delete()
        return Response({'detail': 'Property deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
"""
********************************************************
* Unit Manager APIs                                    *
********************************************************
"""
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_units(request, property_name=None, unit_id=None):
    user = request.user
    
    # Ensure user is a Landlord
    if user.role != 'Landlord':
        return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
    
    # Retrieve properties belonging to the logged-in Landlord
    properties = Property.objects.filter(user=user)
    
    # Handle POST request to add a new unit to a property
    if request.method == 'POST':
        try:
            property_instance = properties.get(property_name=property_name)
        except Property.DoesNotExist:
            return Response({'detail': 'Property not found'}, status=status.HTTP_404_NOT_FOUND)
        
        request.data['property'] = property_instance.id
        serializer = UnitSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Handle GET request to retrieve units
    if request.method == 'GET':
        if unit_id:
            try:
                unit = Unit.objects.get(id=unit_id, property__in=properties)
                serializer = UnitSerializer(unit)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Unit.DoesNotExist:
                return Response({'detail': 'Unit not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            units = Unit.objects.filter(property__in=properties)
            serializer = UnitSerializer(units, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    # Handle PUT request to update a unit
    if request.method == 'PUT':
        try:
            unit = Unit.objects.get(id=unit_id, property__in=properties)
            serializer = UnitSerializer(unit, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Unit.DoesNotExist:
            return Response({'detail': 'Unit not found'}, status=status.HTTP_404_NOT_FOUND)

    # Handle DELETE request to delete a unit
    if request.method == 'DELETE':
        try:
            unit = Unit.objects.get(id=unit_id, property__in=properties)
            unit.delete()
            return Response({'detail': 'Unit deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Unit.DoesNotExist:
            return Response({'detail': 'Unit not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

"""
Lease management APIs
"""
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_leases(request, lease_id=None):
    user = request.user
    
    if request.method == 'POST':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        serializer = LeaseSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if lease_id:
            try:
                if user.role == 'Landlord':
                    lease = Lease.objects.get(id=lease_id, property__user=user)
                else:
                    lease = Lease.objects.get(id=lease_id, tenant=user)
                serializer = LeaseSerializer(lease)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Lease.DoesNotExist:
                return Response({'detail': 'Lease not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            if user.role == 'Landlord':
                leases = Lease.objects.filter(property__user=user)
            else:
                leases = Lease.objects.filter(tenant=user)
            serializer = LeaseSerializer(leases, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            lease = Lease.objects.get(id=lease_id, property__user=user)
            serializer = LeaseSerializer(lease, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Lease.DoesNotExist:
            return Response({'detail': 'Lease not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            lease = Lease.objects.get(id=lease_id, property__user=user)
            lease.delete()
            return Response({'detail': 'Lease deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Lease.DoesNotExist:
            return Response({'detail': 'Lease not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

""" Rent management APIs """
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_rentpayments(request, payment_id=None):
    user = request.user

    if request.method == 'POST':
        if user.role != 'Tenant':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        serializer = RentPaymentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if payment_id:
            try:
                if user.role == 'Landlord':
                    payment = RentPayment.objects.get(id=payment_id, lease__property__user=user)
                else:
                    payment = RentPayment.objects.get(id=payment_id, lease__tenant=user)
                serializer = RentPaymentSerializer(payment)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except RentPayment.DoesNotExist:
                return Response({'detail': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            if user.role == 'Landlord':
                payments = RentPayment.objects.filter(lease__property__user=user)
            else:
                payments = RentPayment.objects.filter(lease__tenant=user)
            serializer = RentPaymentSerializer(payments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        if user.role != 'Tenant':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            payment = RentPayment.objects.get(id=payment_id, lease__tenant=user)
            serializer = RentPaymentSerializer(payment, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except RentPayment.DoesNotExist:
            return Response({'detail': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        if user.role != 'Tenant':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            payment = RentPayment.objects.get(id=payment_id, lease__tenant=user)
            payment.delete()
            return Response({'detail': 'Payment deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except RentPayment.DoesNotExist:
            return Response({'detail': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

""" Maintencance management """
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_maintenancerequests(request, request_id=None):
    user = request.user

    if request.method == 'POST':
        if user.role != 'Tenant':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        serializer = MaintenanceRequestSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if request_id:
            try:
                if user.role == 'Landlord':
                    request_obj = MaintenanceRequest.objects.get(id=request_id, unit__property__user=user)
                else:
                    request_obj = MaintenanceRequest.objects.get(id=request_id, tenant=user)
                serializer = MaintenanceRequestSerializer(request_obj)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except MaintenanceRequest.DoesNotExist:
                return Response({'detail': 'Request not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            if user.role == 'Landlord':
                requests = MaintenanceRequest.objects.filter(unit__property__user=user)
            else:
                requests = MaintenanceRequest.objects.filter(tenant=user)
            serializer = MaintenanceRequestSerializer(requests, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        if user.role != 'Tenant':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            request_obj = MaintenanceRequest.objects.get(id=request_id, tenant=user)
            serializer = MaintenanceRequestSerializer(request_obj, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except MaintenanceRequest.DoesNotExist:
            return Response({'detail': 'Request not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        if user.role != 'Tenant':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            request_obj = MaintenanceRequest.objects.get(id=request_id, tenant=user)
            request_obj.delete()
            return Response({'detail': 'Request deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except MaintenanceRequest.DoesNotExist:
            return Response({'detail': 'Request not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

""" Communication APIs"""
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_messages(request, message_id=None):
    user = request.user

    if request.method == 'POST':
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(sender=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if message_id:
            try:
                message = Message.objects.get(id=message_id, sender=user) | Message.objects.get(id=message_id, receiver=user)
                serializer = MessageSerializer(message)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Message.DoesNotExist:
                return Response({'detail': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            messages = Message.objects.filter(sender=user) | Message.objects.filter(receiver=user)
            serializer = MessageSerializer(messages, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

""" Document Management """
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_documents(request, document_id=None):
    user = request.user

    if request.method == 'POST':
        serializer = DocumentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if document_id:
            try:
                document = Document.objects.get(id=document_id, user=user)
                serializer = DocumentSerializer(document)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Document.DoesNotExist:
                return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            documents = Document.objects.filter(user=user)
            serializer = DocumentSerializer(documents, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        try:
            document = Document.objects.get(id=document_id, user=user)
            serializer = DocumentSerializer(document, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Document.DoesNotExist:
            return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        try:
            document = Document.objects.get(id=document_id, user=user)
            document.delete()
            return Response({'detail': 'Document deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Document.DoesNotExist:
            return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

""" Finacial Management """
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_expenses(request, expense_id=None):
    user = request.user

    if request.method == 'POST':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        serializer = ExpenseSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if expense_id:
            try:
                expense = Expense.objects.get(id=expense_id, property__user=user)
                serializer = ExpenseSerializer(expense)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Expense.DoesNotExist:
                return Response({'detail': 'Expense not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            expenses = Expense.objects.filter(property__user=user)
            serializer = ExpenseSerializer(expenses, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            expense = Expense.objects.get(id=expense_id, property__user=user)
            serializer = ExpenseSerializer(expense, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Expense.DoesNotExist:
            return Response({'detail': 'Expense not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            expense = Expense.objects.get(id=expense_id, property__user=user)
            expense.delete()
            return Response({'detail': 'Expense deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Expense.DoesNotExist:
            return Response({'detail': 'Expense not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

""" Feedback management"""
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_feedback(request, feedback_id=None):
    user = request.user

    if request.method == 'POST':
        serializer = FeedbackSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if feedback_id:
            try:
                feedback = Feedback.objects.get(id=feedback_id, user=user)
                serializer = FeedbackSerializer(feedback)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Feedback.DoesNotExist:
                return Response({'detail': 'Feedback not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            feedbacks = Feedback.objects.filter(user=user)
            serializer = FeedbackSerializer(feedbacks, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

""" Forum Management """
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_forums(request, forum_id=None):
    user = request.user

    if request.method == 'POST':
        serializer = ForumSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if forum_id:
            try:
                forum = Forum.objects.get(id=forum_id)
                serializer = ForumSerializer(forum)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Forum.DoesNotExist:
                return Response({'detail': 'Forum not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            forums = Forum.objects.all()
            serializer = ForumSerializer(forums, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_forum_messages(request, forum_id, message_id=None):
    user = request.user

    if request.method == 'POST':
        try:
            forum = Forum.objects.get(id=forum_id)
            serializer = ForumMessageSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(forum=forum, user=user)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Forum.DoesNotExist:
            return Response({'detail': 'Forum not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        if message_id:
            try:
                message = ForumMessage.objects.get(id=message_id, forum__id=forum_id)
                serializer = ForumMessageSerializer(message)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except ForumMessage.DoesNotExist:
                return Response({'detail': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            messages = ForumMessage.objects.filter(forum__id=forum_id)
            serializer = ForumMessageSerializer(messages, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
