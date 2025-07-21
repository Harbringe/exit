from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from rest_framework.permissions import IsAuthenticated
from django.http import HttpResponse
from .models import VendorProfile
from core.models import Wallet
import qrcode
import io
import json

# Create your views here.

class VendorQRView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            vendor_profile = VendorProfile.objects.get(user=request.user)
        except VendorProfile.DoesNotExist:
            return Response({'error': 'Vendor profile not found.'}, status=status.HTTP_404_NOT_FOUND)
        if not vendor_profile.approved:
            return Response({'error': 'Vendor is not approved.'}, status=status.HTTP_403_FORBIDDEN)
        # Get wallet (assuming one wallet per vendor user)
        wallet = Wallet.objects.filter(user=request.user).first()
        if not wallet:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        qr_data = {
            'vendor_id': vendor_profile.vendor_id,
            'business_name': vendor_profile.business_name,
            'wallet_id': wallet.wallet_id,
        }
        qr_json = json.dumps(qr_data)
        qr_img = qrcode.make(qr_json)
        buf = io.BytesIO()
        qr_img.save(buf, format='PNG')
        buf.seek(0)
        return HttpResponse(buf, content_type='image/png')
