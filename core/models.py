from django.db import models
from django.conf import settings
import uuid
import shortuuid
from django.utils import timezone
from decimal import Decimal
import requests

# Create your models here.

class Wallet(models.Model):
    id = models.AutoField(primary_key=True)
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('suspended', 'Suspended'),
        ('closed', 'Closed'),
    ]
    wallet_id = models.CharField(max_length=22, unique=True, editable=False, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallets')
    balance = models.DecimalField(max_digits=20, decimal_places=2, default=0)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    pin = models.CharField(max_length=6, verbose_name='Wallet PIN')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Wallet'
        verbose_name_plural = 'Wallets'
        db_table = 'wallets'

    def save(self, *args, **kwargs):
        if not self.wallet_id:
            self.wallet_id = shortuuid.uuid()
        if not self.pin or not self.pin.isdigit() or len(self.pin) != 6:
            raise ValueError('Wallet PIN must be a 6-digit number.')
        super().save(*args, **kwargs)

    def deposit(self, amount):
        if self.status != 'active':
            raise ValueError('Wallet is not active.')
        if amount <= 0:
            raise ValueError('Deposit amount must be positive.')
        self.balance += Decimal(str(amount))
        self.save()
        return self.balance

    def withdraw(self, amount):
        if self.status != 'active':
            raise ValueError('Wallet is not active.')
        if amount <= 0:
            raise ValueError('Withdrawal amount must be positive.')
        if self.balance < amount:
            raise ValueError('Insufficient balance.')
        self.balance -= amount
        self.save()
        return self.balance

    def get_balance(self):
        return self.balance

    def __str__(self):
        return f"Wallet {self.wallet_id} for {self.user.email} (Balance: {self.balance})"

class Transaction(models.Model):
    TRANSACTION_TYPE_CHOICES = [
        ('deposit', 'Deposit'),
        ('withdraw', 'Withdraw'),
        ('transfer', 'Transfer'),
        ('spend', 'Spend'),  # For purchasing event tickets and stuff
        ('receive', 'Receive'),  # For receiving payments by event manager/admin/creator
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    amount = models.DecimalField(max_digits=20, decimal_places=2)
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPE_CHOICES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    reference = models.CharField(max_length=64, unique=True, blank=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Transaction'
        verbose_name_plural = 'Transactions'
        db_table = 'transactions'

    def save(self, *args, **kwargs):
        if not self.reference:
            self.reference = shortuuid.uuid()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.transaction_type.title()} of {self.amount} for Wallet {self.wallet.wallet_id} ({self.status})"

class Event(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    image = models.ImageField(upload_to='event_images/', blank=True, null=True)
    location = models.CharField(max_length=255)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    start_datetime = models.DateTimeField()
    end_datetime = models.DateTimeField()
    capacity = models.PositiveIntegerField()
    token_cost = models.PositiveIntegerField(default=0)
    token_reward = models.PositiveIntegerField(default=0)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_events')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        # Geocode location if location is set and lat/lon are not set or location changed
        if self.location:
            try:
                LOCATIONIQ_API_KEY = getattr(settings, 'LOCATIONIQ_API_KEY', None)
                if LOCATIONIQ_API_KEY:
                    url = 'https://us1.locationiq.com/v1/search'
                    params = {
                        'key': LOCATIONIQ_API_KEY,
                        'q': self.location,
                        'format': 'json'
                    }
                    response = requests.get(url, params=params, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if isinstance(data, list) and len(data) > 0:
                            self.latitude = float(data[0].get('lat'))
                            self.longitude = float(data[0].get('lon'))
            except Exception as e:
                pass  # Optionally log the error
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title

class EventRSVP(models.Model):
    RSVP_STATUS_CHOICES = [
        ('interested', 'Interested'),
        ('confirmed', 'Confirmed'),
        ('attended', 'Attended'),
        ('noshow', 'No Show'),
    ]
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='event_rsvps')
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='rsvps')
    status = models.CharField(max_length=10, choices=RSVP_STATUS_CHOICES, default='interested')
    rsvp_time = models.DateTimeField(default=timezone.now)
    attended_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        unique_together = ('user', 'event')

    def __str__(self):
        return f"{self.user} RSVP for {self.event}: {self.status}"
