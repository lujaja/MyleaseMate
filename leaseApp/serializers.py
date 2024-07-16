from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import *
User = get_user_model()
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'role', 'contact', 'profilePic', 'rating']

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)

    class Meta:
        model = User
        fields = ['password', 'first_name', 'last_name', 'email', 'role', 'contact']

    def create(self, validated_data):
        user = User.objects.create(**validated_data)
        # user.set_password(validated_data['password'])
        user.save()
        return user
    def update(self, instance, validated_data):
        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
        return super().update(instance, validated_data)

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'), username=email, password=password)

            if not user:
                raise serializers.ValidationError('Unable to log in with provided credentials.', code='authorization')

            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError('Must include "email" and "password".', code='authorization')


class EmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(max_length=128)

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'contact', 'profile_pic', 'rating']
        read_only_fields = ['email']


class PropertySerializer(serializers.ModelSerializer):
    class Meta:
        model = Property
        fields = ['id', 'user', 'property_name', 'address', 'type', 'size', 'rent_amount',
                  'photos', 'virtual_tour', 'listing_platforms', 'valuation']
        read_only_fields = ['user'] # Mark 'user' field as read-only

class UnitSerializer(serializers.ModelSerializer):
    class Meta:
        model = Unit
        fields = '__all__'
    
class LeaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lease
        fields = '__all__'

class RentPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = RentPayment
        fields = '__all__'

class MaintenanceRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = MaintenanceRequest
        fields = '__all__'

class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = '__all__'

class DocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = '__all__'

class ExpenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Expense
        fields = '__all__'

class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = '__all__'

class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = '__all__'

class TenantScreeningSerializer(serializers.ModelSerializer):
    class Meta:
        model = TenantScreening
        fields = '__all__'

class ForumSerializer(serializers.ModelSerializer):
    class Meta:
        model = Forum
        fields = '__all__'

class ForumMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ForumMessage
        fields = '__all__'