from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, UserProfile

class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'
    fields = ('image', 'full_name', 'country', 'about', 'date_of_birth', 'gender', 'age', 'user_type', 'phone_number')

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('id', 'email', 'user_type', 'phone_number', 'is_active', 'date_joined')
    list_filter = ('user_type', 'is_active', 'is_staff', 'date_joined')
    search_fields = ('email', 'phone_number')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('phone_number',)}),
        ('Account Type', {'fields': ('user_type',)}),
        ('Security', {'fields': ('otp', 'refresh_token')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'user_type', 'phone_number', 'password1', 'password2'),
        }),
    )
    
    readonly_fields = ('id', 'date_joined', 'last_login')
    inlines = (UserProfileInline,)
    
    def full_name(self, obj):
        return obj.full_name
    full_name.short_description = 'Full Name'

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'display_name', 'country', 'gender', 'user_type', 'created_at')
    list_filter = ('user_type', 'gender', 'country', 'created_at')
    search_fields = ('user__email', 'user__phone_number', 'full_name', 'country')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('User Information', {'fields': ('user',)}),
        ('Personal Information', {'fields': ('image', 'full_name', 'gender', 'age', 'date_of_birth')}),
        ('Contact Information', {'fields': ('phone_number', 'country')}),
        ('Account Information', {'fields': ('user_type', 'about')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at'), 'classes': ('collapse',)}),
    )
    
    def display_name(self, obj):
        return obj.display_name
    display_name.short_description = 'Display Name'
