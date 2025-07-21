from django.urls import path
from . import views
from .views import (
    EventListView, EventCreateView, EventRSVPCreateUpdateView, EventRSVPListView,
)

app_name = 'api'

urlpatterns = [
    # User module endpoints
    path('user/register/', views.UserRegistrationView.as_view(), name='user_register'),
    path('user/token/web/', views.UserLoginView.as_view(), name='user_token_web'),
    path('user/token/mobile/generate-otp/', views.MobileTokenGenerateOtpView.as_view(), name='user_token_mobile_generate_otp'),
    path('user/token/mobile/', views.MobileTokenObtainView.as_view(), name='user_token_mobile'),
    path('user/token/refresh/', views.RefreshTokenView.as_view(), name='user_token_refresh'),
    path('user/logout/', views.LogoutView.as_view(), name='user_logout'),

    # Password management
    path('user/password-reset/web/', views.PasswordResetView.as_view(), name='user_password_reset_web'),
    path('user/password-reset/mobile/', views.MobilePasswordResetView.as_view(), name='user_password_reset_mobile'),
    path('user/password-reset/confirm/web/', views.PasswordResetConfirmView.as_view(), name='user_password_reset_confirm_web'),
    path('user/password-reset/confirm/mobile/', views.MobilePasswordResetConfirmView.as_view(), name='user_password_reset_confirm_mobile'),
    path('user/password-change/web/', views.ChangePasswordView.as_view(), name='user_password_change_web'),
    path('user/password-change/mobile/', views.MobileChangePasswordView.as_view(), name='user_password_change_mobile'),

    # User profile management
    path('user/profile/<int:user_id>/', views.UserProfileView.as_view(), name='profile'),
    path('user/onboarding/', views.OnboardingView.as_view(), name='user_onboarding'),

    # Wallet endpoints
    path('wallet/generate-otp/', views.WalletGenerateOtpView.as_view(), name='wallet_generate_otp'),
    path('wallet/create/', views.WalletCreateView.as_view(), name='wallet_create'),
    path('wallet/deposit/', views.WalletDepositView.as_view(), name='wallet_deposit'),
    path('wallet/withdraw/', views.WalletWithdrawView.as_view(), name='wallet_withdraw'),
    path('wallet/balance/', views.WalletBalanceView.as_view(), name='wallet_balance'),
    path('wallet/transactions/', views.WalletTransactionListView.as_view(), name='wallet_transactions'),
    path('wallet/deposit/initiate/', views.WalletRazorpayDepositInitiateView.as_view(), name='wallet_deposit_initiate'),
    path('wallet/deposit/confirm/', views.WalletRazorpayDepositConfirmView.as_view(), name='wallet_deposit_confirm'),
    path('wallet/id/', views.GetWalletIdView.as_view(), name='wallet_id'),

    # Event endpoints
    path('events/', EventListView.as_view(), name='event_list'),
    path('events/create/', EventCreateView.as_view(), name='event_create'),
    path('events/<int:event_id>/rsvp/', EventRSVPCreateUpdateView.as_view(), name='event_rsvp'),
    path('events/rsvps/', EventRSVPListView.as_view(), name='event_rsvp_list'),
]