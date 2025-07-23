import io
import json
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone

import qrcode
from rest_framework import generics, permissions, status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import VendorProfile, KYC, Category, Product
from core.models import Wallet

from .serializers import (
    KYCSerializer,
    CategorySerializer,
    VendorProfileSerializer,
    ProductSerializer,
)


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

class KYCListCreateView(generics.ListCreateAPIView):
    serializer_class = KYCSerializer
    parser_classes = (MultiPartParser, FormParser)

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return KYC.objects.all().order_by('-submitted_on')
        return KYC.objects.filter(user=user).order_by('-submitted_on')

    @swagger_auto_schema(
        operation_description="List KYC submissions. Users see their own, admins see all.",
        responses={200: KYCSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Submit a new KYC document.",
        request_body=KYCSerializer,
        responses={201: KYCSerializer}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user, submitted_on=timezone.now())

class KYCVerifyView(generics.UpdateAPIView):
    queryset = KYC.objects.all()
    serializer_class = KYCSerializer
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Verify a KYC submission (admin only).",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'verified': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='Set to true to verify'),
            },
            required=['verified']
        ),
        responses={200: KYCSerializer}
    )
    def patch(self, request, *args, **kwargs):
        kyc = self.get_object()
        verified = request.data.get('verified')
        if verified is not None:
            kyc.verified = bool(verified)
            kyc.verified_on = timezone.now() if kyc.verified else None
            kyc.save()
        serializer = self.get_serializer(kyc)
        return Response(serializer.data)

class CategoryListView(generics.ListAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="List all vendor categories.",
        responses={200: CategorySerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

class VendorProfileRetrieveUpdateView(generics.RetrieveUpdateAPIView):
    serializer_class = VendorProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return VendorProfile.objects.get(user=self.request.user)

    @swagger_auto_schema(
        operation_description="Retrieve the authenticated vendor's profile.",
        responses={200: VendorProfileSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Update the authenticated vendor's profile. Use 'category_id' to set category.",
        request_body=VendorProfileSerializer,
        responses={200: VendorProfileSerializer}
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

class ProductListView(generics.ListAPIView):
    queryset = Product.objects.all().order_by('-created_at')
    serializer_class = ProductSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="List all products.",
        responses={200: ProductSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

class ProductRetrieveView(generics.RetrieveAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Retrieve a product by ID.",
        responses={200: ProductSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

class ProductCreateView(generics.CreateAPIView):
    serializer_class = ProductSerializer
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new product (vendor only).",
        request_body=ProductSerializer,
        responses={201: ProductSerializer}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def perform_create(self, serializer):
        vendor_profile = VendorProfile.objects.get(user=self.request.user)
        serializer.save(vendor=vendor_profile)

class ProductUpdateDeleteView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ProductSerializer
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return Product.objects.none()
        vendor_profile = VendorProfile.objects.get(user=self.request.user)
        return Product.objects.filter(vendor=vendor_profile)

    @swagger_auto_schema(
        operation_description="Retrieve, update, or delete a product (vendor only, must own the product).",
        responses={200: ProductSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Update a product (vendor only, must own the product).",
        request_body=ProductSerializer,
        responses={200: ProductSerializer}
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Delete a product (vendor only, must own the product).",
        responses={204: 'No Content'}
    )
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)
