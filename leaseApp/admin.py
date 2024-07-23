from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

class UserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email', 'contact', 'profilePic', 'rating')}),
        ('Permissions', {'fields': ('isActive', 'isApproved', 'role', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('Two Factor Authentication', {'fields': ('twoFactorAuth',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'email', 'first_name', 'last_name', 'contact', 'profilePic', 'rating', 'role', 'is_active', 'is_approved', 'twoFactorAuth')}
        ),
    )

    list_display = ('username', 'email', 'first_name', 'last_name', 'is_active', 'is_approved', 'role')
    search_fields = ('email', 'first_name', 'last_name', 'username')
    readonly_fields = ('date_joined', 'last_login')
    ordering = ('email',)
    

admin.site.register(User, UserAdmin)

