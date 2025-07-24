from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from userauths.models import User
from vendor.models import VendorProfile, KYC, Category, CommissionCategory
from vendor.serializers import VendorProfileSerializer, KYCSerializer, CommissionCategorySerializer
from core.models import Transaction, Wallet, Event, EventRSVP
from django.http import HttpResponse
import csv
from api.serializers import EventSerializer
from api.serializers import EventRSVPSerializer
from django.db.models import Sum, Count, F

# Create your views here.

class IsAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and getattr(request.user, 'user_type', None) == 'admin'

class AdminOnboardingDashboardView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Admin dashboard overview",
        operation_description="""
        Returns a summary of key admin metrics for onboarding and monitoring purposes.
        - Only accessible by admin users.
        - Includes counts for vendor approvals, commission categories, wallets, event bookings, sustainability metrics, and real-time transactions.
        """,
        responses={
            200: openapi.Response(
                description="Admin dashboard data.",
                examples={
                    "application/json": {
                        'vendor_approvals': 5,
                        'commission_categories': 3,
                        'wallets': 100,
                        'event_bookings': 20,
                        'sustainability_metrics': {},
                        'real_time_transactions': 50,
                    }
                }
            )
        }
    )
    def get(self, request):
        # Placeholder: return summary data for admin dashboard
        return Response({
            'vendor_approvals': 0,
            'commission_categories': 0,
            'wallets': 0,
            'event_bookings': 0,
            'sustainability_metrics': {},
            'real_time_transactions': 0,
        }, status=status.HTTP_200_OK)

class AdminVendorListView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="List all vendors",
        operation_description="""
        Returns a list of all vendors, including both pending and approved vendors.
        - Only accessible by admin users.
        - Useful for vendor management and monitoring.
        """,
        responses={
            200: openapi.Response(
                description="List of vendors.",
                schema=VendorProfileSerializer(many=True),
                examples={
                    "application/json": [
                        {
                            "id": 1,
                            "vendor_id": "abc123",
                            "user": 2,
                            "business_name": "Vendor A",
                            "approved": True,
                            "kyc_verified": True,
                            "category": {"id": 1, "name": "Food"},
                            # ... other fields ...
                        }
                    ]
                }
            ),
            403: "Forbidden: Only admin users can access this endpoint."
        }
    )
    def get(self, request):
        vendors = VendorProfile.objects.all().order_by('-created_at')
        serializer = VendorProfileSerializer(vendors, many=True)
        return Response(serializer.data)

class AdminVendorApproveView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Approve or reject a vendor",
        operation_description="""
        Approve or reject a pending vendor application.
        - Only accessible by admin users.
        - Pass `approved: true` to approve, `approved: false` to reject.
        """,
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'approved': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='Set to true to approve, false to reject the vendor.'),
            },
            required=['approved'],
            example={'approved': True}
        ),
        responses={
            200: openapi.Response(
                description="Vendor approval status updated.",
                schema=VendorProfileSerializer,
                examples={
                    "application/json": {
                        "id": 1,
                        "vendor_id": "abc123",
                        "user": 2,
                        "business_name": "Vendor A",
                        "approved": True,
                        "kyc_verified": True,
                        "category": {"id": 1, "name": "Food"},
                        # ... other fields ...
                    }
                }
            ),
            400: "Missing or invalid input.",
            404: "Vendor not found.",
            403: "Forbidden: Only admin users can access this endpoint."
        }
    )
    def patch(self, request, vendor_id):
        try:
            vendor = VendorProfile.objects.get(id=vendor_id)
        except VendorProfile.DoesNotExist:
            return Response({'error': 'Vendor not found.'}, status=status.HTTP_404_NOT_FOUND)
        approved = request.data.get('approved')
        if approved is None:
            return Response({'error': 'Missing approved field.'}, status=status.HTTP_400_BAD_REQUEST)
        vendor.approved = bool(approved)
        vendor.save()
        serializer = VendorProfileSerializer(vendor)
        return Response(serializer.data)

class AdminVendorKYCListView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="List all KYC documents for a vendor",
        operation_description="""
        Returns all KYC documents submitted by a specific vendor.
        - Only accessible by admin users.
        - Useful for compliance and verification.
        """,
        responses={
            200: openapi.Response(
                description="List of KYC documents.",
                schema=KYCSerializer(many=True),
                examples={
                    "application/json": [
                        {
                            "id": 1,
                            "user": 2,
                            "document_type": "passport",
                            "document_number": "A1234567",
                            "verified": True,
                            # ... other fields ...
                        }
                    ]
                }
            ),
            404: "Vendor not found.",
            403: "Forbidden: Only admin users can access this endpoint."
        }
    )
    def get(self, request, vendor_id):
        try:
            vendor = VendorProfile.objects.get(id=vendor_id)
        except VendorProfile.DoesNotExist:
            return Response({'error': 'Vendor not found.'}, status=status.HTTP_404_NOT_FOUND)
        kyc_docs = KYC.objects.filter(user=vendor.user).order_by('-submitted_on')
        serializer = KYCSerializer(kyc_docs, many=True)
        return Response(serializer.data)

class AdminVendorCategoryUpdateView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Assign or modify a vendor's category",
        operation_description="""
        Assigns or updates the category for a specific vendor.
        - Only accessible by admin users.
        - Provide a valid category ID in the request body.
        """,
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'category_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Category ID'),
            },
            required=['category_id'],
            example={'category_id': 1}
        ),
        responses={
            200: openapi.Response(
                description="Vendor category updated.",
                schema=VendorProfileSerializer,
                examples={
                    "application/json": {
                        "id": 1,
                        "vendor_id": "abc123",
                        "user": 2,
                        "business_name": "Vendor A",
                        "category": {"id": 1, "name": "Food"},
                        # ... other fields ...
                    }
                }
            ),
            400: "Missing or invalid input.",
            404: "Vendor or category not found.",
            403: "Forbidden: Only admin users can access this endpoint."
        }
    )
    def patch(self, request, vendor_id):
        try:
            vendor = VendorProfile.objects.get(id=vendor_id)
        except VendorProfile.DoesNotExist:
            return Response({'error': 'Vendor not found.'}, status=status.HTTP_404_NOT_FOUND)
        category_id = request.data.get('category_id')
        try:
            category = Category.objects.get(id=category_id)
        except Category.DoesNotExist:
            return Response({'error': 'Category not found.'}, status=status.HTTP_404_NOT_FOUND)
        vendor.category = category
        vendor.save()
        serializer = VendorProfileSerializer(vendor)
        return Response(serializer.data)

class AdminVendorSalesView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="View vendor sales volume and transaction count",
        operation_description="""
        Returns the total sales and transaction count for a specific vendor.
        - Only accessible by admin users.
        - Useful for monitoring vendor performance.
        """,
        responses={
            200: openapi.Response(
                description="Vendor sales data.",
                examples={
                    "application/json": {
                        'vendor_id': 1,
                        'total_sales': '1000.00',
                        'transaction_count': 25
                    }
                }
            ),
            404: "Vendor or wallet not found.",
            403: "Forbidden: Only admin users can access this endpoint."
        }
    )
    def get(self, request, vendor_id):
        try:
            vendor = VendorProfile.objects.get(id=vendor_id)
        except VendorProfile.DoesNotExist:
            return Response({'error': 'Vendor not found.'}, status=status.HTTP_404_NOT_FOUND)
        wallet = Wallet.objects.filter(user=vendor.user).first()
        if not wallet:
            return Response({'error': 'Vendor wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        transactions = Transaction.objects.filter(wallet=wallet, transaction_type='receive')
        total_sales = sum(t.amount for t in transactions)
        return Response({
            'vendor_id': vendor_id,
            'total_sales': str(total_sales),
            'transaction_count': transactions.count(),
        })

class AdminVendorExportTransactionsView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Export vendor's transaction history as CSV",
        operation_description="""
        Exports all transactions for a specific vendor as a downloadable CSV file.
        - Only accessible by admin users.
        - Useful for audits and reporting.
        """,
        responses={
            200: openapi.Response(
                description="CSV file containing vendor transactions.",
                examples={
                    "text/csv": "Amount,Type,Status,Reference,Description,Created At\n100,receive,completed,ref123,Payment,2024-06-01T12:00:00Z\n"
                }
            ),
            404: "Vendor or wallet not found.",
            403: "Forbidden: Only admin users can access this endpoint."
        }
    )
    def get(self, request, vendor_id):
        try:
            vendor = VendorProfile.objects.get(id=vendor_id)
        except VendorProfile.DoesNotExist:
            return Response({'error': 'Vendor not found.'}, status=status.HTTP_404_NOT_FOUND)
        wallet = Wallet.objects.filter(user=vendor.user).first()
        if not wallet:
            return Response({'error': 'Vendor wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        transactions = Transaction.objects.filter(wallet=wallet).order_by('-created_at')
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="vendor_{vendor_id}_transactions.csv"'
        writer = csv.writer(response)
        writer.writerow(['Amount', 'Type', 'Status', 'Reference', 'Description', 'Created At'])
        for t in transactions:
            writer.writerow([t.amount, t.transaction_type, t.status, t.reference, t.description, t.created_at])
        return response

class AdminVendorBlacklistView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Blacklist or report a vendor",
        operation_description="""
        Blacklists or reports a vendor for non-compliance or other issues.
        - Only accessible by admin users.
        - Optionally provide a report reason.
        """,
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'blacklisted': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='Blacklist vendor'),
                'report_reason': openapi.Schema(type=openapi.TYPE_STRING, description='Reason for report'),
            },
            required=['blacklisted'],
            example={'blacklisted': True, 'report_reason': 'Fraudulent activity'}
        ),
        responses={
            200: openapi.Response(
                description="Vendor blacklisted or reported.",
                schema=VendorProfileSerializer,
                examples={
                    "application/json": {
                        "id": 1,
                        "vendor_id": "abc123",
                        "user": 2,
                        "business_name": "Vendor A",
                        "blacklisted": True,
                        # ... other fields ...
                    }
                }
            ),
            400: "Missing or invalid input.",
            404: "Vendor not found.",
            403: "Forbidden: Only admin users can access this endpoint."
        }
    )
    def patch(self, request, vendor_id):
        try:
            vendor = VendorProfile.objects.get(id=vendor_id)
        except VendorProfile.DoesNotExist:
            return Response({'error': 'Vendor not found.'}, status=status.HTTP_404_NOT_FOUND)
        blacklisted = request.data.get('blacklisted')
        report_reason = request.data.get('report_reason', '')
        vendor.blacklisted = bool(blacklisted)
        if report_reason:
            vendor.business_description += f"\n[ADMIN REPORT]: {report_reason}"
        vendor.save()
        serializer = VendorProfileSerializer(vendor)
        return Response(serializer.data)

class AdminCommissionCategoryListCreateView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="List all commission categories and their splits.",
        responses={200: CommissionCategorySerializer(many=True)}
    )
    def get(self, request):
        commissions = CommissionCategory.objects.select_related('category').all().order_by('category__name')
        serializer = CommissionCategorySerializer(commissions, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Create a commission split for a category. Accepts JSON: { 'category': <id>, 'vendor_percent': 80, 'admin_percent': 20 }",
        request_body=CommissionCategorySerializer,
        responses={201: CommissionCategorySerializer}
    )
    def post(self, request):
        serializer = CommissionCategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminCommissionCategoryUpdateView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Update commission split for a category. Accepts JSON: { 'vendor_percent': 80, 'admin_percent': 20 }",
        request_body=CommissionCategorySerializer,
        responses={200: CommissionCategorySerializer}
    )
    def patch(self, request, pk):
        try:
            commission = CommissionCategory.objects.get(pk=pk)
        except CommissionCategory.DoesNotExist:
            return Response({'error': 'Commission category not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = CommissionCategorySerializer(commission, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminWalletListView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="List all wallets.",
        responses={200: openapi.Response(description="List of wallets")}
    )
    def get(self, request):
        wallets = Wallet.objects.select_related('user').all().order_by('-created_at')
        data = [
            {
                'id': w.id,
                'wallet_id': w.wallet_id,
                'user_id': w.user.id,
                'user_email': w.user.email,
                'balance': str(w.balance),
                'status': w.status,
                'created_at': w.created_at,
                'updated_at': w.updated_at,
            }
            for w in wallets
        ]
        return Response(data)

class AdminWalletDetailView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Get wallet details by wallet_id.",
        responses={200: openapi.Response(description="Wallet details")}
    )
    def get(self, request, wallet_id):
        try:
            wallet = Wallet.objects.select_related('user').get(wallet_id=wallet_id)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        data = {
            'id': wallet.id,
            'wallet_id': wallet.wallet_id,
            'user_id': wallet.user.id,
            'user_email': wallet.user.email,
            'balance': str(wallet.balance),
            'status': wallet.status,
            'created_at': wallet.created_at,
            'updated_at': wallet.updated_at,
        }
        return Response(data)

class AdminWalletStatusUpdateView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Change wallet status (suspend, activate, close). Accepts JSON: { 'status': 'active'|'suspended'|'closed' }",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'status': openapi.Schema(type=openapi.TYPE_STRING, description='New status'),
            },
            required=['status']
        ),
        responses={200: openapi.Response(description="Updated wallet")}
    )
    def patch(self, request, wallet_id):
        try:
            wallet = Wallet.objects.get(wallet_id=wallet_id)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        status_val = request.data.get('status')
        if status_val not in dict(Wallet.STATUS_CHOICES):
            return Response({'error': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)
        wallet.status = status_val
        wallet.save()
        return Response({'wallet_id': wallet.wallet_id, 'status': wallet.status})

class AdminEventListView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="List all events.",
        responses={200: EventSerializer(many=True)}
    )
    def get(self, request):
        events = Event.objects.select_related('created_by').all().order_by('-start_datetime')
        serializer = EventSerializer(events, many=True)
        return Response(serializer.data)

class AdminEventDetailView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Get event details by event_id.",
        responses={200: EventSerializer}
    )
    def get(self, request, event_id):
        try:
            event = Event.objects.select_related('created_by').get(id=event_id)
        except Event.DoesNotExist:
            return Response({'error': 'Event not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = EventSerializer(event)
        return Response(serializer.data)

class AdminEventRSVPListView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="List all RSVPs for an event.",
        responses={200: EventRSVPSerializer(many=True)}
    )
    def get(self, request, event_id):
        rsvps = EventRSVP.objects.select_related('user', 'event').filter(event_id=event_id).order_by('-rsvp_time')
        serializer = EventRSVPSerializer(rsvps, many=True)
        return Response(serializer.data)

class AdminSustainabilityMetricsView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Get sustainability metrics (placeholder/stub).",
        responses={200: openapi.Response(description="Sustainability metrics")}
    )
    def get(self, request):
        total_events = Event.objects.count()
        total_rsvps = EventRSVP.objects.count()
        unique_users = EventRSVP.objects.values('user').distinct().count()
        # Placeholder for eco challenge stats, etc.
        return Response({
            'total_events': total_events,
            'total_rsvps': total_rsvps,
            'unique_users': unique_users,
            'eco_challenges': [],  # To be implemented
        })

class AdminTransactionMonitoringView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Get real-time transaction monitoring data.",
        responses={200: openapi.Response(description="Transaction monitoring data")}
    )
    def get(self, request):
        total_transactions = Transaction.objects.count()
        total_revenue = Transaction.objects.filter(transaction_type='receive', status='completed').aggregate(total=Sum('amount'))['total'] or 0
        # Revenue split by vendor category
        category_split = (
            VendorProfile.objects
            .values('category__name')
            .annotate(
                total=Sum('user__wallets__transactions__amount', filter=F('user__wallets__transactions__transaction_type')=='receive'),
                count=Count('user__wallets__transactions', filter=F('user__wallets__transactions__transaction_type')=='receive')
            )
            .order_by('-total')
        )
        # Total admin earnings (sum of all 'receive' transactions for admin wallets)
        admin_earnings = Transaction.objects.filter(wallet__user__user_type='admin', transaction_type='receive', status='completed').aggregate(total=Sum('amount'))['total'] or 0
        # Loyalty redemptions (stub: count of 'spend' transactions with description containing 'loyalty')
        loyalty_redemptions = Transaction.objects.filter(transaction_type='spend', description__icontains='loyalty').count()
        # Peak time (stub: hour with most transactions)
        peak_hour = (
            Transaction.objects.annotate(hour=F('created_at__hour'))
            .values('hour').annotate(count=Count('id')).order_by('-count').first()
        )
        # Repeat customers (users with >1 'spend' transaction)
        repeat_customers = (
            Transaction.objects.filter(transaction_type='spend')
            .values('wallet__user').annotate(count=Count('id')).filter(count__gt=1).count()
        )
        # Top performing vendors (by revenue)
        top_vendors = (
            VendorProfile.objects
            .annotate(revenue=Sum('user__wallets__transactions__amount', filter=F('user__wallets__transactions__transaction_type')=='receive'))
            .order_by('-revenue')[:5]
            .values('id', 'business_name', 'revenue')
        )
        return Response({
            'total_transactions': total_transactions,
            'total_revenue': str(total_revenue),
            'category_split': list(category_split),
            'admin_earnings': str(admin_earnings),
            'loyalty_redemptions': loyalty_redemptions,
            'peak_hour': peak_hour['hour'] if peak_hour else None,
            'repeat_customers': repeat_customers,
            'top_vendors': list(top_vendors),
        })

class AdminFlaggedTransactionListView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="List all flagged transactions (simulated: transactions with 'flag' or 'dispute' in description).",
        responses={200: openapi.Response(description="Flagged transactions")}
    )
    def get(self, request):
        flagged = Transaction.objects.filter(description__icontains='flag').union(
            Transaction.objects.filter(description__icontains='dispute')
        ).order_by('-created_at')
        data = [
            {
                'id': t.id,
                'wallet_id': t.wallet.wallet_id,
                'user_email': t.wallet.user.email,
                'amount': str(t.amount),
                'type': t.transaction_type,
                'status': t.status,
                'description': t.description,
                'created_at': t.created_at,
            }
            for t in flagged
        ]
        return Response(data)

class AdminTransactionRefundView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Initiate a refund for a transaction. Accepts JSON: { 'refund_reason': <str> }",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refund_reason': openapi.Schema(type=openapi.TYPE_STRING, description='Reason for refund'),
            },
            required=['refund_reason']
        ),
        responses={200: openapi.Response(description="Refund processed")}
    )
    def post(self, request, transaction_id):
        try:
            tx = Transaction.objects.get(id=transaction_id)
        except Transaction.DoesNotExist:
            return Response({'error': 'Transaction not found.'}, status=status.HTTP_404_NOT_FOUND)
        refund_reason = request.data.get('refund_reason', '')
        # Only allow refund if not already refunded
        if tx.status == 'refunded':
            return Response({'error': 'Transaction already refunded.'}, status=status.HTTP_400_BAD_REQUEST)
        # Refund logic: credit back to wallet if spend, debit if receive (simulate)
        wallet = tx.wallet
        if tx.transaction_type == 'spend':
            wallet.deposit(tx.amount)
        elif tx.transaction_type == 'receive':
            wallet.withdraw(tx.amount)
        tx.status = 'refunded'
        tx.description += f"\n[REFUND]: {refund_reason}"
        tx.save()
        return Response({'transaction_id': tx.id, 'status': tx.status})

class AdminSuspendWalletView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Suspend a wallet (set status to 'suspended').",
        responses={200: openapi.Response(description="Wallet suspended")}
    )
    def post(self, request, wallet_id):
        try:
            wallet = Wallet.objects.get(wallet_id=wallet_id)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        wallet.status = 'suspended'
        wallet.save()
        return Response({'wallet_id': wallet.wallet_id, 'status': wallet.status})
