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
    # Override username to be non-unique and optional
    username = models.CharField(max_length=150, unique=False, null=True, blank=True)

    email = models.EmailField(unique=True)  # Ensure email is unique
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=False)
    is_approved = models.BooleanField(default=False)
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

    USERNAME_FIELD = 'email'  # Use email as the username field
    REQUIRED_FIELDS = ['first_name', 'last_name', 'role']  # Fields required for creating a user

    def save(self, *args, **kwargs):
        if self.pk is None or 'password' in self.get_dirty_fields():
            print(f"Hashing password for user: {self.email}")
            self.set_password(self.password)
        super().save(*args, **kwargs)

    def check_password(self, raw_password: str) -> bool:
        print(f"Checking password for user: {self.email}")
        return check_password(raw_password, self.password)

    def __str__(self) -> str:
        return f"Email: {self.email}, First Name: {self.first_name}, Last Name: {self.last_name}"

class Property(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='properties')
    property_name = models.CharField(max_length=128)
    address = models.TextField()
    type = models.CharField(max_length=50)
    size = models.FloatField()
    rent_amount = models.DecimalField(max_digits=10, decimal_places=2)
    photos = models.JSONField()
    virtual_tour = models.URLField(null=True, blank=True)
    listing_platforms = models.JSONField()
    valuation = models.FloatField()

    def __str__(self):
        return self.property_name

class Unit(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='units')
    unit_number = models.CharField(max_length=10)
    floor = models.IntegerField()
    size = models.FloatField()
    status = models.CharField(
        max_length=50,
        choices=[
            ('Available', 'Available'),
            ('Occupied', 'Occupied'),
        ]
    )
    rent_amount = models.DecimalField(max_digits=10, decimal_places=2)
    availability = models.JSONField()

class Lease(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='leases')
    unit = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name='leases')
    tenant = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tenant_leases')
    landlord = models.ForeignKey(User, on_delete=models.CASCADE, related_name='landlord_leases')
    lease_start_date = models.DateField()
    lease_end_date = models.DateField()
    rent_amount = models.DecimalField(max_digits=10, decimal_places=2)
    security_deposit = models.DecimalField(max_digits=10, decimal_places=2)
    payment_frequency = models.CharField(max_length=50)
    lease_terms = models.TextField()
    renewal_terms = models.TextField(null=True, blank=True)
    pet_policy = models.TextField(null=True, blank=True)
    maintenance_responsibility = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=[('active', 'Active'), ('pending', 'Pending'), ('terminated', 'Terminated')])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    utilities_included = models.BooleanField(default=False)
    services_included = models.TextField(null=True, blank=True)

    def __str__(self):
        return f'Lease for {self.unit} by {self.tenant}'

class Rent_Payment(models.Model):
    lease = models.ForeignKey(Lease, on_delete=models.CASCADE, related_name='rent_payments')
    payment_date = models.DateField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=20, choices=[('Cash', 'Cash'), ('Credit Card', 'Credit Card'), ('Bank Transfer', 'Bank Transfer')])
    receipt = models.URLField()
    late_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    transaction_id = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"Payment for {self.lease} on {self.payment_date}"

class Maintenance_Request(models.Model):
    unit = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name='maintenance_requests')
    tenant = models.ForeignKey(User, on_delete=models.CASCADE, related_name='maintenance_requests')
    description = models.TextField()
    request_date = models.DateField()
    status = models.CharField(max_length=15, choices=[('Pending', 'Pending'), ('In Progress', 'In Progress'), ('Completed', 'Completed')])
    assigned_vendor = models.ForeignKey('Vendor', on_delete=models.SET_NULL, null=True, blank=True, related_name='maintenance_requests')
    feedback = models.TextField(null=True, blank=True)
    predictive_alert = models.BooleanField(default=False)

    def __str__(self):
        return f"Request for {self.unit} by {self.tenant.username}"

class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    attachments = models.JSONField()
class Document(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='documents')
    lease = models.ForeignKey(Lease, on_delete=models.SET_NULL, null=True, blank=True, related_name='documents')
    document_type = models.CharField(max_length=50)
    file_path = models.URLField()
    expiry_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"Document {self.document_type} for {self.user.username}"

class Expense(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='expenses')
    description = models.TextField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField()

    def __str__(self):
        return f"Expense for {self.property.name} on {self.date}"

class Feedback(models.Model):
    given_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='given_feedback')
    for_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_feedback')
    rating = models.FloatField()
    comments = models.TextField()

    def __str__(self):
        return f"Feedback by {self.given_by.username} for {self.for_user.username}"

class Vendor(models.Model):
    name = models.CharField(max_length=100)
    contact_information = models.TextField()
    rating = models.FloatField(default=0)
    preferred = models.BooleanField(default=False)

    def __str__(self):
        return self.name

class Tenant_Screening(models.Model):
    tenant = models.ForeignKey(User, on_delete=models.CASCADE, related_name='screenings')
    background_check_result = models.JSONField()
    credit_check_result = models.JSONField()
    reference_verification = models.JSONField()
    risk_score = models.FloatField()

    def __str__(self):
        return f"Screening for {self.tenant.username}"

class Forum(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='forums')
    topic = models.CharField(max_length=200)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_forums')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Forum {self.topic} for {self.property.name}"

class Forum_Message(models.Model):
    forum = models.ForeignKey(Forum, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='forum_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    attachments = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"Message in {self.forum.topic} by {self.sender.username}"