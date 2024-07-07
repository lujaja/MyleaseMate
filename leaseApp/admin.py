from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

class UserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('firstName', 'lastName', 'email', 'contact', 'profilePic', 'rating')}),
        ('Permissions', {'fields': ('isActive', 'isApproved', 'role', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('Two Factor Authentication', {'fields': ('twoFactorAuth',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'email', 'firstName', 'lastName', 'contact', 'profilePic', 'rating', 'role', 'isActive', 'isApproved', 'twoFactorAuth')}
        ),
    )

    list_display = ('username', 'email', 'firstName', 'lastName', 'isActive', 'isApproved', 'role')
    search_fields = ('email', 'firstName', 'lastName', 'username')
    ordering = ('email',)

admin.site.register(User, UserAdmin)

