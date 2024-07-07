
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.contrib.auth.hashers import make_password, check_password

class User(AbstractUser):
    """ Deifne Class User"""
    ROLE_CHOICES = [
        ('Landlord', 'Landlord'),
        ('Tenant', 'Tenant'),
        ('Admin', 'Admin'),
    ]
    userName = models.CharField(max_length=150)
    password = models.CharField(max_length=128)
    firstName = models.CharField(max_length=100)
    lastName = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    isActive = models.BooleanField(default=False)
    isApproved = models.BooleanField(default=False)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    contact = models.TextField()
    twoFactorAuth = models.BooleanField(default=False)
    profilePic = models.URLField(null=True, blank=True)
    rating = models.FloatField(default=0)
    groups = models.ManyToManyField(
        Group,
        related_name='leaseapp_user_set',
        blank=True,
        help_text=(
            'The groups this user belongs to.'
            'A user will get all permission granted to each of there groups'
        ),
        verbose_name=('groups'),
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='leaseapp_user_permission_set',
        blank=True,
        help_text=('Specific permission for this User.'),
        verbose_name=('User permissions'),
    )

    def save(self, *args, **kwargs):
        if not self.pk:
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password)
    
    def __str__(self) -> str:
        return "UserName: {}, Email: ".format(self.username, self.email)


class Property(models.Model):
    """ Define Class property"""
    landlordID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='properties')
    propertyName = models.CharField(max_length=128)
    address = models.TextField()
    type = models.CharField(max_length=50)
    size = models.FloatField()
    rentAmount = models.DecimalField(max_digits=10, decimal_places=2)
    photos = models.JSONField()
    virtualTour = models.URLField(null=True, blank=True)
    listingPlatforms = models.JSONField()
    valuation = models.FloatField()

    def __str__(self) -> str:
        return "Property Name: , Owned by {}".format(self.propertyName, self.landlordID.userName)

class Unit(models.Model):
    propertyiD = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='units')
    unitNumber = models.CharField(max_length=10)
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
    rentAmount = models.DecimalField(max_digits=10, decimal_places=2)
    availabilityCalendar = models.JSONField()

class Lease(models.Model):
    unitID = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name='leases')
    tenantID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='leases')
    startDate = models.DateField()
    endDate = models.DateField(null=True)
    rentAmount = models.DecimalField(max_digits=10, decimal_places=2)
    signeDocument = models.URLField()
    renewalReminder = models.DateField()

class RentPayment(models.Model):
    leaseID = models.ForeignKey(Lease, on_delete=models.CASCADE, related_name='rent_payments')
    paymentDate = models.DateField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    paymentMethod = models.CharField(max_length=20)
    receipt = models.URLField()
    lateFee = models.DecimalField(max_digits=10, decimal_places=2, default=0)

class MaintenanceRequest(models.Model):
    unitID = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name='maintenance_requests')
    tenantID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='maintenance_requests')
    description = models.TextField()
    request_date = models.DateField()
    status = models.CharField(max_length=15, choices=[('Pending', 'Pending'), ('In Progress', 'In Progress'), ('Completed', 'Completed')])
    assignedVendor = models.ForeignKey('Vendor', on_delete=models.SET_NULL, null=True, blank=True, related_name='maintenance_requests')
    feedback = models.TextField(null=True, blank=True)
    predictivAlert = models.BooleanField(default=False)

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
    backgroundCheckResult = models.JSONField()
    creditCheckResult = models.JSONField()
    referenceVerification = models.JSONField()
    riskScore = models.FloatField()

class Forum(models.Model):
    propertyID = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='forums')
    topic = models.CharField(max_length=200)
    createdBy = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_forums')
    createdAt = models.DateTimeField(auto_now_add=True)

class ForumMessage(models.Model):
    forumID = models.ForeignKey(Forum, on_delete=models.CASCADE, related_name='messages')
    senderID = models.ForeignKey(User, on_delete=models.CASCADE, related_name='forum_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    attachments = models.JSONField()
