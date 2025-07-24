from django.contrib import admin
from .models import VendorProfile, KYC, Category, Product, CommissionCategory

admin.site.register(VendorProfile)
admin.site.register(CommissionCategory)

@admin.register(KYC)
class KYCAdmin(admin.ModelAdmin):
    list_display = ('user', 'document_type', 'document_number', 'verified', 'verified_on', 'submitted_on')
    search_fields = ('user__email', 'document_number')
    list_filter = ('verified', 'document_type')

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'vendor', 'price_tokens', 'stock', 'created_at')
    search_fields = ('name', 'vendor__business_name')
    list_filter = ('vendor',)

# Register your models here.
