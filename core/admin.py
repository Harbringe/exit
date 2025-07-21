from django.contrib import admin
from .models import Wallet, Transaction, Event, EventRSVP

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

@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'start_datetime', 'end_datetime', 'capacity', 'token_cost', 'token_reward', 'created_by', 'created_at')
    search_fields = ('title', 'location', 'description')
    list_filter = ('start_datetime', 'end_datetime', 'location')

@admin.register(EventRSVP)
class EventRSVPAdmin(admin.ModelAdmin):
    list_display = ('user', 'event', 'status', 'rsvp_time', 'attended_at')
    search_fields = ('user__email', 'event__title')
    list_filter = ('status', 'event')
