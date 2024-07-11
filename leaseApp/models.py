from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.contrib.auth.hashers import check_password
from dirtyfields import DirtyFieldsMixin

class User(AbstractUser, DirtyFieldsMixin):
    ROLE_CHOICES = [
        ('Landlord', 'Landlord'),
        ('Tenant', 'Tenant'),
        ('Admin', 'Admin'),
    ]

    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    is_approved = models.BooleanField(default=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    contact = models.TextField()
    two_factor_auth = models.BooleanField(default=False)
    profile_pic = models.URLField(null=True, blank=True)
    rating = models.FloatField(default=0)
    verification_code = models.CharField(max_length=6, blank=True, null=True)
    groups = models.ManyToManyField(
        Group,
        related_name='leaseapp_user_set',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='leaseapp_user_permission_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

    def save(self, *args, **kwargs):
        if self.pk is None or 'password' in self.get_dirty_fields():
            print(f"Hashing password for user: {self.email}")
            self.set_password(self.password)
        super().save(*args, **kwargs)


    def check_password(self, raw_password: str) -> bool:
        print(f"Checking password for user: {self.email}")
        print(f'self.paswword->{self.password}')
        print(f'raw password->{raw_password}')
        return check_password(raw_password, self.password)

    def __str__(self) -> str:
        return f"UserName: {self.username}, Email: {self.email}"

class Property(models.Model):
    landlordID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='properties')
    property_name = models.CharField(max_length=128)
    address = models.TextField()
    type = models.CharField(max_length=50)
    size = models.FloatField()
    rent_amount = models.DecimalField(max_digits=10, decimal_places=2)
    photos = models.JSONField()
    virtual_tour = models.URLField(null=True, blank=True)
    listing_platforms = models.JSONField()
    valuation = models.FloatField()

    def __str__(self) -> str:
        return f"Property Name: {self.propertyName}, Owned by {self.landlordID.userName}"

class Unit(models.Model):
    propertyiD = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='units')
    unit_number = models.CharField(max_length=10)
    floor = models.IntegerField()
    size = models.FloatField()
    status = models.CharField(
        max_length=50,
        choices=[
            ('Available', 'Available'),
            ('Occupied', 'Occupied'),
            ('Maintenance', 'Maintenance')
        ]
    )
    rent_amount = models.DecimalField(max_digits=10, decimal_places=2)
    availability = models.JSONField()

class Lease(models.Model):
    unitID = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name='leases')
    tenantID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='leases')
    start_date = models.DateField()
    end_date = models.DateField(null=True)
    rent_amount = models.DecimalField(max_digits=10, decimal_places=2)
    signe_document = models.URLField()
    renewal_reminder = models.DateField()

class RentPayment(models.Model):
    leaseID = models.ForeignKey(Lease, on_delete=models.CASCADE, related_name='rent_payments')
    payment_date = models.DateField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=20)
    receipt = models.URLField()
    late_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)

class MaintenanceRequest(models.Model):
    unitID = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name='maintenance_requests')
    tenantID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='maintenance_requests')
    description = models.TextField()
    request_date = models.DateField()
    status = models.CharField(max_length=15, choices=[('Pending', 'Pending'), ('In Progress', 'In Progress'), ('Completed', 'Completed')])
    assigned_vendor = models.ForeignKey('Vendor', on_delete=models.SET_NULL, null=True, blank=True, related_name='maintenance_requests')
    feedback = models.TextField(null=True, blank=True)
    predictive_alert = models.BooleanField(default=False)

class Message(models.Model):
    senderID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiverID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    attachments = models.JSONField()

class Document(models.Model):
    userID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='documents')
    leaseID = models.ForeignKey(Lease, on_delete=models.SET_NULL, null=True, blank=True, related_name='documents')
    document_type = models.CharField(max_length=50)
    file_path = models.URLField()
    expiry_date = models.DateField()

class Expense(models.Model):
    propertyID = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='expenses')
    description = models.TextField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField()

class Feedback(models.Model):
    givenBy = models.ForeignKey(User, on_delete=models.CASCADE, related_name='given_feedback')
    forUser = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_feedback')
    rating = models.FloatField()
    comments = models.TextField()

class Vendor(models.Model):
    name = models.CharField(max_length=100)
    contact_information = models.TextField()
    rating = models.FloatField(default=0)
    preferred = models.BooleanField(default=False)

class TenantScreening(models.Model):
    tenantID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='screenings')
    background_check_result = models.JSONField()
    credit_check_result = models.JSONField()
    reference_verification = models.JSONField()
    risk_score = models.FloatField()

class Forum(models.Model):
    propertyID = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='forums')
    topic = models.CharField(max_length=200)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_forums')
    created_at = models.DateTimeField(auto_now_add=True)

class ForumMessage(models.Model):
    forumID = models.ForeignKey(Forum, on_delete=models.CASCADE, related_name='messages')
    senderID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='forum_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    attachments = models.JSONField()
