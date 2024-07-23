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
from .tasks import *
# import Serializers here after adding them in the named file
from .serializers import *
# import all tasks allocated to celery here
from .tasks import *

User = get_user_model()
# status ok API
@api_view(['GET'])
def status_view(request):
    return Response({'status': 'OK'}, status=status.HTTP_200_OK)

"""
********************************************************
* User Manager APIs                                    *
********************************************************
"""
@api_view(['GET'])
def status_view(request):
    return Response({'status': 'OK'}, status=status.HTTP_200_OK)

# Register user Endpoint
# tested and working
@api_view(['POST'])
def register(request):
    serializer = UserRegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        code = get_random_string(length=6, allowed_chars='0123456789')
        print(f'User verification code {code}')
        user.verification_code = code
        user.save()
        send_verification_email(user.email, code)
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
        
        # Check if the user's account is verified
        if not user.is_active:
            return Response({'detail': 'Please verify your account before logging in.'}, status=status.HTTP_403_FORBIDDEN)
        
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
            send_verification_email(user.email, verification_code)
        
        return Response(tokens, status=status.HTTP_200_OK)
    print(serializer.errors)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# email verification after account creation
# Tested and not sending email
@api_view(['POST', 'GET'])
def verify_email(request):
    if request.method == 'GET':
        email = request.query_params.get('email')
        if not email:
            return Response({'detail': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
            if user.is_active:
                return Response({'detail': 'Email is already verified'}, status=status.HTTP_400_BAD_REQUEST)
            code = get_random_string(length=6, allowed_chars='0123456789')
            user.verification_code = code
            print(f'User verification code {code}')
            user.save()
            send_verification_email(user.email, code)
            return Response({'detail': 'Verification email sent'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    elif request.method == 'POST':
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(email=serializer.validated_data['email'])
                if user.verification_code == serializer.validated_data['code']:
                    user.is_active = True
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
            print(f'User password reset code {code}')
            user.verification_code = code
            user.save()
            send_password_reset_email(user.email, code)
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
                user.password = serializer.validated_data['new_password']
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
    if request.method == 'POST':
        if request.user.role != 'Landlord':
            return Response({'detail': 'Only landlords can manage properties'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = PropertySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    if request.method == 'GET':
        if request.user.role == 'Landlord':
            properties = Property.objects.filter(user=request.user)
        else:  # Tenant can view all properties
            properties = Property.objects.all()
        
        serializer = PropertySerializer(properties, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def property_details(request, property_id):
    try:
        property = Property.objects.get(id=property_id)
    except Property.DoesNotExist:
        return Response({'detail': 'Property not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = PropertySerializer(property)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    if request.method == 'PUT':
        if request.user.role != 'Landlord':
            return Response({'detail': 'Only landlords can edit properties'}, status=status.HTTP_403_FORBIDDEN)

        serializer = PropertySerializer(property, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()

            # Example: Call Celery task asynchronously
            new_valuation = serializer.validated_data.get('valuation')
            if new_valuation:
                update_property_valuation(property.id, new_valuation)

            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    if request.method == 'DELETE':
        if request.user.role != 'Landlord':
            return Response({'detail': 'Only landlords can delete properties'}, status=status.HTTP_403_FORBIDDEN)
        
        property.delete()
        return Response({'detail': 'Property deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
"""
********************************************************
* Unit Manager APIs                                    *
********************************************************
"""
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_units(request, property_id=None, unit_id=None):
    user = request.user

    # Ensure user is authenticated
    if not user.is_authenticated:
        return Response({'detail': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

    # Handle POST request to add a new unit to a property
    if request.method == 'POST':
        if user.role != 'Landlord':
            return Response({'detail': 'Only landlords can add units'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            property_instance = Property.objects.get(id=request.data.get('property_id'), user=user)
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
                unit = Unit.objects.get(id=unit_id)
                serializer = UnitSerializer(unit)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Unit.DoesNotExist:
                return Response({'detail': 'Unit not found'}, status=status.HTTP_404_NOT_FOUND)
        elif property_id:
            try:
                property_instance = Property.objects.get(id=property_id)
                units = Unit.objects.filter(property_id=property_id)
                serializer = UnitSerializer(units, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Property.DoesNotExist:
                return Response({'detail': 'Property not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            if user.role == 'Landlord':
                properties = Property.objects.filter(user=user)
                units = Unit.objects.filter(property__in=properties)
            else:
                units = Unit.objects.all()
            serializer = UnitSerializer(units, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    # Handle PUT request to update a unit
    if request.method == 'PUT':
        if user.role != 'Landlord':
            return Response({'detail': 'Only landlords can update units'}, status=status.HTTP_403_FORBIDDEN)

        property_id = request.data.get('property_id', None)  # Allow updating property_id
        if property_id:
            try:
                property_instance = Property.objects.get(id=property_id, user=user)
            except Property.DoesNotExist:
                return Response({'detail': 'Property not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            unit = Unit.objects.get(id=unit_id, property__user=user)
            serializer = UnitSerializer(unit, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Unit.DoesNotExist:
            return Response({'detail': 'Unit not found'}, status=status.HTTP_404_NOT_FOUND)

    # Handle DELETE request to delete a unit
    if request.method == 'DELETE':
        if user.role != 'Landlord':
            return Response({'detail': 'Only landlords can delete units'}, status=status.HTTP_403_FORBIDDEN)

        try:
            unit = Unit.objects.get(id=unit_id, property__user=user)
            unit.delete()
            return Response({'detail': 'Unit deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Unit.DoesNotExist:
            return Response({'detail': 'Unit not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Views for managing Lease objects
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_leases(request, lease_id=None):
    user = request.user

    if request.method == 'POST':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)

        # Ensure all required fields are present
        required_fields = [
            'property', 'unit', 'tenant', 'landlord', 'lease_start_date', 'lease_end_date', 
            'rent_amount', 'security_deposit', 'payment_frequency', 'lease_terms'
        ]
        for field in required_fields:
            if field not in request.data:
                return Response({f'{field}': 'This field is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate foreign keys
        property_id = request.data.get('property')
        unit_id = request.data.get('unit')
        tenant_id = request.data.get('tenant')
        landlord_id = request.data.get('landlord')

        try:
            Property.objects.get(id=property_id)
            Unit.objects.get(id=unit_id)
            User.objects.get(id=tenant_id)
            User.objects.get(id=landlord_id)
        except Property.DoesNotExist:
            return Response({'detail': 'Property not found'}, status=status.HTTP_404_NOT_FOUND)
        except Unit.DoesNotExist:
            return Response({'detail': 'Unit not found'}, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = LeaseSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'GET':
        if lease_id:
            try:
                lease = Lease.objects.get(id=lease_id)
                if (user.role == 'Landlord' and lease.landlord == user) or (user.role == 'Tenant' and lease.tenant == user):
                    serializer = LeaseSerializer(lease)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            except Lease.DoesNotExist:
                return Response({'detail': 'Lease not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            if user.role == 'Landlord':
                leases = Lease.objects.filter(landlord=user)
            else:
                leases = Lease.objects.filter(tenant=user)
            serializer = LeaseSerializer(leases, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            lease = Lease.objects.get(id=lease_id)
            if lease.landlord != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            serializer = LeaseSerializer(lease, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Lease.DoesNotExist:
            return Response({'detail': 'Lease not found'}, status=status.HTTP_404_NOT_FOUND)

    elif request.method == 'DELETE':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)

        try:
            lease = Lease.objects.get(id=lease_id)
            if lease.landlord != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            lease.delete()
            return Response({'detail': 'Lease deleted'}, status=status.HTTP_204_NO_CONTENT)
        except Lease.DoesNotExist:
            return Response({'detail': 'Lease not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
# Views for managing RentPayment objects
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
                payment = Rent_Payment.objects.get(id=payment_id)
                if (user.role == 'Landlord' and payment.lease.landlord == user) or (user.role == 'Tenant' and payment.lease.tenant == user):
                    serializer = RentPaymentSerializer(payment)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            except Rent_Payment.DoesNotExist:
                return Response({'detail': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            if user.role == 'Landlord':
                payments = Rent_Payment.objects.filter(lease__landlord=user)
            else:
                payments = Rent_Payment.objects.filter(lease__tenant=user)
            serializer = RentPaymentSerializer(payments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        if user.role != 'Tenant':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            payment = Rent_Payment.objects.get(id=payment_id)
            if payment.lease.tenant != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            serializer = RentPaymentSerializer(payment, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Rent_Payment.DoesNotExist:
            return Response({'detail': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        if user.role != 'Tenant':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            payment = Rent_Payment.objects.get(id=payment_id)
            if payment.lease.tenant != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            payment.delete()
            return Response({'detail': 'Payment deleted'}, status=status.HTTP_204_NO_CONTENT)
        except Rent_Payment.DoesNotExist:
            return Response({'detail': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Views for managing MaintenanceRequest objects
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
                    request_obj = Maintenance_Request.objects.get(id=request_id, unit__property__user=user)
                else:
                    request_obj = Maintenance_Request.objects.get(id=request_id, tenant=user)
                serializer = MaintenanceRequestSerializer(request_obj)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Maintenance_Request.DoesNotExist:
                return Response({'detail': 'Request not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            if user.role == 'Landlord':
                requests = Maintenance_Request.objects.filter(unit__property__user=user)
            else:
                requests = Maintenance_Request.objects.filter(tenant=user)
            serializer = MaintenanceRequestSerializer(requests, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        if user.role != 'Tenant':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            request_obj = Maintenance_Request.objects.get(id=request_id, tenant=user)
            serializer = MaintenanceRequestSerializer(request_obj, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Maintenance_Request.DoesNotExist:
            return Response({'detail': 'Request not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        if user.role != 'Tenant':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            request_obj = Maintenance_Request.objects.get(id=request_id, tenant=user)
            request_obj.delete()
            return Response({'detail': 'Request deleted'}, status=status.HTTP_204_NO_CONTENT)
        except Maintenance_Request.DoesNotExist:
            return Response({'detail': 'Request not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Views for managing Message objects
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
                message = Message.objects.get(id=message_id)
                if message.sender == user or message.receiver == user:
                    serializer = MessageSerializer(message)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            except Message.DoesNotExist:
                return Response({'detail': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            messages = Message.objects.filter(sender=user) | Message.objects.filter(receiver=user)
            serializer = MessageSerializer(messages, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        try:
            message = Message.objects.get(id=message_id)
            if message.sender != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            serializer = MessageSerializer(message, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Message.DoesNotExist:
            return Response({'detail': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        try:
            message = Message.objects.get(id=message_id)
            if message.sender != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            message.delete()
            return Response({'detail': 'Message deleted'}, status=status.HTTP_204_NO_CONTENT)
        except Message.DoesNotExist:
            return Response({'detail': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Views for managing Document objects
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_documents(request, document_id=None):
    user = request.user

    if request.method == 'POST':
        serializer = DocumentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(uploaded_by=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if document_id:
            try:
                document = Document.objects.get(id=document_id)
                if document.uploaded_by == user:
                    serializer = DocumentSerializer(document)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            except Document.DoesNotExist:
                return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            documents = Document.objects.filter(uploaded_by=user)
            serializer = DocumentSerializer(documents, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        try:
            document = Document.objects.get(id=document_id)
            if document.uploaded_by != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            serializer = DocumentSerializer(document, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Document.DoesNotExist:
            return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        try:
            document = Document.objects.get(id=document_id)
            if document.uploaded_by != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            document.delete()
            return Response({'detail': 'Document deleted'}, status=status.HTTP_204_NO_CONTENT)
        except Document.DoesNotExist:
            return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Views for managing Expense objects
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
                expense = Expense.objects.get(id=expense_id)
                if expense.unit.property.user == user:
                    serializer = ExpenseSerializer(expense)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            except Expense.DoesNotExist:
                return Response({'detail': 'Expense not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            expenses = Expense.objects.filter(unit__property__user=user)
            serializer = ExpenseSerializer(expenses, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            expense = Expense.objects.get(id=expense_id)
            if expense.unit.property.user != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
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
            expense = Expense.objects.get(id=expense_id)
            if expense.unit.property.user != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            expense.delete()
            return Response({'detail': 'Expense deleted'}, status=status.HTTP_204_NO_CONTENT)
        except Expense.DoesNotExist:
            return Response({'detail': 'Expense not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Views for managing Feedback objects
@api_view(['POST', 'GET'])
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
                feedback = Feedback.objects.get(id=feedback_id)
                if feedback.tenant == user or feedback.unit.property.user == user:
                    serializer = FeedbackSerializer(feedback)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            except Feedback.DoesNotExist:
                return Response({'detail': 'Feedback not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            feedbacks = Feedback.objects.filter(tenant=user) | Feedback.objects.filter(unit__property__user=user)
            serializer = FeedbackSerializer(feedbacks, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Views for managing Vendor objects
@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def manage_vendors(request, vendor_id=None):
    user = request.user

    if request.method == 'POST':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        serializer = VendorSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if vendor_id:
            try:
                vendor = Vendor.objects.get(id=vendor_id)
                if vendor.unit.property.user == user:
                    serializer = VendorSerializer(vendor)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            except Vendor.DoesNotExist:
                return Response({'detail': 'Vendor not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            vendors = Vendor.objects.filter(unit__property__user=user)
            serializer = VendorSerializer(vendors, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            vendor = Vendor.objects.get(id=vendor_id)
            if vendor.unit.property.user != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            serializer = VendorSerializer(vendor, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Vendor.DoesNotExist:
            return Response({'detail': 'Vendor not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        if user.role != 'Landlord':
            return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
        try:
            vendor = Vendor.objects.get(id=vendor_id)
            if vendor.unit.property.user != user:
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            vendor.delete()
            return Response({'detail': 'Vendor deleted'}, status=status.HTTP_204_NO_CONTENT)
        except Vendor.DoesNotExist:
            return Response({'detail': 'Vendor not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Views for managing TenantScreening objects
@api_view(['POST', 'GET'])
@permission_classes([IsAuthenticated])
def manage_tenant_screening(request, screening_id=None):
    user = request.user

    if request.method == 'POST':
        serializer = TenantScreeningSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if screening_id:
            try:
                screening = Tenant_Screening.objects.get(id=screening_id)
                if screening.unit.property.user == user:
                    serializer = TenantScreeningSerializer(screening)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            except Tenant_Screening.DoesNotExist:
                return Response({'detail': 'Screening not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            screenings = Tenant_Screening.objects.filter(unit__property__user=user)
            serializer = TenantScreeningSerializer(screenings, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Views for managing Forum objects
@api_view(['POST', 'GET'])
@permission_classes([IsAuthenticated])
def manage_forum(request, forum_id=None):
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
                if forum.unit.property.user == user or user in forum.tenants.all():
                    serializer = ForumSerializer(forum)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            except Forum.DoesNotExist:
                return Response({'detail': 'Forum not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            forums = Forum.objects.filter(unit__property__user=user) | Forum.objects.filter(tenants=user)
            serializer = ForumSerializer(forums, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Views for managing ForumMessage objects
@api_view(['POST', 'GET'])
@permission_classes([IsAuthenticated])
def manage_forum_messages(request, forum_id=None, message_id=None):
    user = request.user

    if request.method == 'POST':
        serializer = ForumMessageSerializer(data=request.data)
        if serializer.is_valid():
            forum = Forum.objects.get(id=request.data['forum'])
            if forum.unit.property.user != user and user not in forum.tenants.all():
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        if message_id:
            try:
                message = Forum_Message.objects.get(id=message_id)
                if message.forum.unit.property.user == user or user in message.forum.tenants.all():
                    serializer = ForumMessageSerializer(message)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
            except Forum_Message.DoesNotExist:
                return Response({'detail': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            try:
                forum = Forum.objects.get(id=forum_id)
                if forum.unit.property.user != user and user not in forum.tenants.all():
                    return Response({'detail': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)
                messages = Forum_Message.objects.filter(forum=forum)
                serializer = ForumMessageSerializer(messages, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Forum.DoesNotExist:
                return Response({'detail': 'Forum not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
