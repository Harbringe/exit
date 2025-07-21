from django.urls import path
from .views import VendorQRView

urlpatterns = [
    path('qr/', VendorQRView.as_view(), name='vendor_qr'),
] 