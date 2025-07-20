from django.db import models
from django.conf import settings
import uuid
import shortuuid

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
        self.balance += amount
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
