# Imports
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.utils.crypto import get_random_string

# import Serializers here after adding them in the named file
from .serializers import (
    UserRegisterSerializer,
    UserLoginSerializer,
    EmailVerificationSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    UserProfileSerializer
)

# import all tasks alloctaed to celery here
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
    serializer = UserLoginSerializer(data=request.data, context={'request': request})
    
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Check if two-factor authentication is enabled for the user
        if user.twoFactorAuth:
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
        if user.twoFactorAuth:
            verification_code = get_random_string(length=6, allowed_chars='0123456789')
            print(f'verification code {verification_code} sent to {user.email}')
            send_verification_email.delay(user.email, verification_code)
        
        return Response(tokens, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# email verification after account creaton
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
        print(f'Receavd get request -> {request.data}')
        return Response(serializer.data, status=status.HTTP_200_OK)
    elif request.method == 'PUT':
        print(f'Receavd put request -> {request.data}')
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
* Unit Manager APIs                                    *
********************************************************
"""

