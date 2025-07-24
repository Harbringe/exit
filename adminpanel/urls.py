from django.urls import path
from .views import AdminOnboardingDashboardView, AdminVendorListView, AdminVendorApproveView, AdminVendorKYCListView, AdminVendorCategoryUpdateView, AdminVendorSalesView, AdminVendorExportTransactionsView, AdminVendorBlacklistView, AdminCommissionCategoryListCreateView, AdminCommissionCategoryUpdateView, AdminWalletListView, AdminWalletDetailView, AdminWalletStatusUpdateView, AdminEventListView, AdminEventDetailView, AdminEventRSVPListView, AdminSustainabilityMetricsView, AdminTransactionMonitoringView, AdminFlaggedTransactionListView, AdminTransactionRefundView, AdminSuspendWalletView

urlpatterns = [
    path('dashboard/', AdminOnboardingDashboardView.as_view(), name='admin_dashboard'),
    path('vendors/', AdminVendorListView.as_view(), name='admin_vendor_list'),
    path('vendors/<int:vendor_id>/approve/', AdminVendorApproveView.as_view(), name='admin_vendor_approve'),
    path('vendors/<int:vendor_id>/kyc/', AdminVendorKYCListView.as_view(), name='admin_vendor_kyc_list'),
    path('vendors/<int:vendor_id>/category/', AdminVendorCategoryUpdateView.as_view(), name='admin_vendor_category_update'),
    path('vendors/<int:vendor_id>/sales/', AdminVendorSalesView.as_view(), name='admin_vendor_sales'),
    path('vendors/<int:vendor_id>/export/', AdminVendorExportTransactionsView.as_view(), name='admin_vendor_export'),
    path('vendors/<int:vendor_id>/blacklist/', AdminVendorBlacklistView.as_view(), name='admin_vendor_blacklist'),
    path('commission-categories/', AdminCommissionCategoryListCreateView.as_view(), name='admin_commission_category_list_create'),
    path('commission-categories/<int:pk>/', AdminCommissionCategoryUpdateView.as_view(), name='admin_commission_category_update'),
    path('wallets/', AdminWalletListView.as_view(), name='admin_wallet_list'),
    path('wallets/<str:wallet_id>/', AdminWalletDetailView.as_view(), name='admin_wallet_detail'),
    path('wallets/<str:wallet_id>/status/', AdminWalletStatusUpdateView.as_view(), name='admin_wallet_status_update'),
    path('wallets/<str:wallet_id>/suspend/', AdminSuspendWalletView.as_view(), name='admin_suspend_wallet'),
    path('events/', AdminEventListView.as_view(), name='admin_event_list'),
    path('events/<int:event_id>/', AdminEventDetailView.as_view(), name='admin_event_detail'),
    path('events/<int:event_id>/rsvps/', AdminEventRSVPListView.as_view(), name='admin_event_rsvp_list'),
    path('sustainability-metrics/', AdminSustainabilityMetricsView.as_view(), name='admin_sustainability_metrics'),
    path('transaction-monitoring/', AdminTransactionMonitoringView.as_view(), name='admin_transaction_monitoring'),
    path('flagged-transactions/', AdminFlaggedTransactionListView.as_view(), name='admin_flagged_transactions'),
    path('transactions/<int:transaction_id>/refund/', AdminTransactionRefundView.as_view(), name='admin_transaction_refund'),
] 