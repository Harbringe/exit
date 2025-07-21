from django.db import models
from django.conf import settings
from django.utils import timezone
import shortuuid

# Create your models here.

def generate_vendor_id():
    return shortuuid.uuid()

class VendorProfile(models.Model):
    vendor_id = models.CharField(max_length=22, unique=True, null=True, blank=True)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='vendor_profile')
    business_name = models.CharField(max_length=255, blank=True)
    business_description = models.TextField(blank=True)
    logo = models.ImageField(upload_to='vendor_logos/', blank=True, null=True)
    contact_email = models.EmailField(blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    kyc_verified = models.BooleanField(default=False)
    approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    def save(self, *args, **kwargs):
        if not self.vendor_id:
            self.vendor_id = generate_vendor_id()
        # Auto-populate fields from user if not set
        if not self.business_name and self.user:
            self.business_name = self.user.get_full_name() or self.user.username
        if not self.contact_email and self.user:
            self.contact_email = self.user.email
        if not self.phone_number and self.user:
            if hasattr(self.user, 'phone_number'):
                self.phone_number = self.user.phone_number
        super().save(*args, **kwargs)

    def __str__(self):
        return self.business_name or str(self.user)
