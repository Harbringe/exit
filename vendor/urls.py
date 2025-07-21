from django.urls import path
from .views import VendorQRView, KYCListCreateView, KYCVerifyView, CategoryListView, VendorProfileRetrieveUpdateView, ProductListView, ProductRetrieveView, ProductCreateView, ProductUpdateDeleteView

urlpatterns = [
    path('qr/', VendorQRView.as_view(), name='vendor_qr'),
    path('kyc/', KYCListCreateView.as_view(), name='kyc_list_create'),
    path('kyc/<int:pk>/verify/', KYCVerifyView.as_view(), name='kyc_verify'),
    path('categories/', CategoryListView.as_view(), name='category_list'),
    path('profile/', VendorProfileRetrieveUpdateView.as_view(), name='vendor_profile'),
    path('products/', ProductListView.as_view(), name='product_list'),
    path('products/<int:pk>/', ProductRetrieveView.as_view(), name='product_detail'),
    path('products/create/', ProductCreateView.as_view(), name='product_create'),
    path('products/<int:pk>/manage/', ProductUpdateDeleteView.as_view(), name='product_manage'),
] 