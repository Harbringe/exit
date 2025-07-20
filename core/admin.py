from django.contrib import admin
from .models import Wallet, Transaction

@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = ('wallet_id', 'user', 'balance', 'status', 'created_at', 'updated_at')
    search_fields = ('wallet_id', 'user__email')
    list_filter = ('status', 'created_at')

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('reference', 'wallet', 'amount', 'transaction_type', 'status', 'created_at')
    search_fields = ('reference', 'wallet__wallet_id', 'wallet__user__email')
    list_filter = ('transaction_type', 'status', 'created_at')
