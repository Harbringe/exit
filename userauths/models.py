from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver
import uuid

# Create your models here.

class CustomUserManager(BaseUserManager):
    def create_user(self, email, user_type, phone_number, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        if not user_type:
            raise ValueError('The User Type field must be set')
        if not phone_number:
            raise ValueError('The Phone Number field must be set')
        
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            user_type=user_type,
            phone_number=phone_number,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, phone_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('user_type', 'admin')
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        user_type = extra_fields.pop('user_type', 'admin')
        return self.create_user(email, user_type, phone_number, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    USER_TYPE_CHOICES = [
        ('customer', 'Customer'),
        ('vendor', 'Vendor'),
        ('admin', 'Admin'),
    ]
    
    # Auto-incrementing ID field
    id = models.AutoField(primary_key=True)
    email = models.EmailField(unique=True, verbose_name="Email Address")
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, verbose_name="User Type")
    phone_number = models.CharField(max_length=15, verbose_name="Phone Number")
    
    # New onboarding status field
    onboardingStatus = models.BooleanField(default=False, verbose_name="Onboarding Status")
    
    # Authentication and security fields
    otp = models.CharField(max_length=6, blank=True, null=True, verbose_name="OTP")
    refresh_token = models.TextField(blank=True, null=True, verbose_name="Refresh Token") 

    # Django auth fields
    is_active = models.BooleanField(default=True, verbose_name="Active")
    is_staff = models.BooleanField(default=False, verbose_name="Staff Status")
    date_joined = models.DateTimeField(default=timezone.now, verbose_name="Date Joined")
    last_login = models.DateTimeField(blank=True, null=True, verbose_name="Last Login")
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['user_type', 'phone_number']
    
    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        db_table = 'users'
    
    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        # Ensure email is always lowercase
        self.email = self.email.lower()
        super().save(*args, **kwargs)

class UserProfile(models.Model):
    GENDER_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
        ('prefer_not_to_say', 'Prefer not to say'),
    ]
    
    USER_TYPE_CHOICES = [
        ('customer', 'Customer'),
        ('vendor', 'Vendor'),
        ('admin', 'Admin'),
    ]
    
    # One-to-one relationship with User
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile', verbose_name="User")
    
    # Profile fields
    image = models.ImageField(upload_to='user_profiles/', blank=True, null=True, verbose_name="Profile Image")
    full_name = models.CharField(max_length=100, blank=True, null=True, verbose_name="Full Name")
    country = models.CharField(max_length=100, blank=True, null=True, verbose_name="Country")
    about = models.TextField(blank=True, null=True, verbose_name="About")
    date_of_birth = models.DateField(blank=True, null=True, verbose_name="Date of Birth")
    gender = models.CharField(max_length=20, choices=GENDER_CHOICES, blank=True, null=True, verbose_name="Gender")
    age = models.PositiveIntegerField(blank=True, null=True, verbose_name="Age")
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, blank=True, null=True, verbose_name="User Type")
    phone_number = models.CharField(max_length=15, blank=True, null=True, verbose_name="Phone Number")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")
    
    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
        db_table = 'user_profiles'
    
    def __str__(self):
        return f"{self.user.email}'s Profile"
    
    def save(self, *args, **kwargs):
        # Auto-populate fields from user if not set
        if not self.user_type and self.user:
            self.user_type = self.user.user_type
        if not self.phone_number and self.user:
            self.phone_number = self.user.phone_number
            
        super().save(*args, **kwargs)
    
    @property
    def display_name(self):
        """Return the best available name for display"""
        if self.full_name:
            return self.full_name
        else:
            return self.user.email

# Signals to automatically create/update UserProfile
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create UserProfile when User is created"""
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Update UserProfile when User is updated"""
    if hasattr(instance, 'profile'):
        instance.profile.save()
    else:
        UserProfile.objects.create(user=instance)
