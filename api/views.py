from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
import random
import string
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from twilio.rest import Client
import requests
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, HtmlContent, Content
from core.models import Wallet, Transaction, Event, EventRSVP
import razorpay
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    ChangePasswordSerializer,
    UserSerializer,
    MobileTokenObtainSerializer,
    MobilePasswordResetSerializer,
    MobilePasswordResetConfirmSerializer,
    MobileChangePasswordSerializer,
    WalletCreateSerializer,
    WalletDepositSerializer,
    WalletWithdrawSerializer,
    WalletBalanceSerializer,
    WalletGenerateOtpSerializer,
    WalletRazorpayDepositInitiateSerializer,
    WalletRazorpayDepositConfirmSerializer,
    OnboardingSerializer,
    EventSerializer,
    EventRSVPSerializer,
)
from rest_framework.permissions import BasePermission
from django.utils import timezone
import qrcode
import io
import json
import base64

# Utility function to send SMS via Twilio
def send_otp_sms(phone_number, otp):
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=f"Your OTP is: {otp}",
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        return True
    except Exception as e:
        print(f"Twilio SMS error: {e}")
        return False

# Utility function to send email via SendGrid
def send_email_with_sendgrid(to_email, subject, html_content, text_content=None, from_email=None, from_name=None):
    """
    Send email using SendGrid API following official guide
    """
    try:
        from_email = from_email or settings.SENDGRID_FROM_EMAIL
        from_name = from_name or settings.SENDGRID_FROM_NAME
        sg = sendgrid.SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)
        from_email_obj = Email(from_email, from_name)
        to_email_obj = To(to_email)
        html_content_obj = HtmlContent(html_content)
        mail = Mail(from_email_obj, to_email_obj, subject, html_content_obj)
        if text_content:
            text_content_obj = Content("text/plain", text_content)
            mail.add_content(text_content_obj)
        response = sg.send(mail)
        if response.status_code in [200, 201, 202]:
            print(f"Email sent successfully to {to_email}")
            print(f"SendGrid Response Status: {response.status_code}")
            return True
        else:
            print(f"Failed to send email. Status code: {response.status_code}")
            print(f"Response body: {response.body}")
            return False
    except Exception as e:
        print(f"Error sending email with SendGrid: {str(e)}")
        return False

# Utility function to send OTP email using SendGrid
def send_otp_email(email, otp, context=None):
    subject = "Your OTP Code"
    # Use a custom HTML template for the email
    context = context or {}
    context.update({'otp': otp, 'email': email})
    html_content = render_to_string('emails/password_reset_otp.html', context)
    text_content = f"Your OTP is: {otp}"
    return send_email_with_sendgrid(email, subject, html_content, text_content)

from userauths.models import User, UserProfile
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    ChangePasswordSerializer,
    UserSerializer,
    MobileTokenObtainSerializer,
    MobilePasswordResetSerializer,
    MobilePasswordResetConfirmSerializer,
    MobileChangePasswordSerializer,
    WalletCreateSerializer,
    WalletDepositSerializer,
    WalletWithdrawSerializer,
    WalletBalanceSerializer,
    WalletGenerateOtpSerializer,
    WalletRazorpayDepositInitiateSerializer,
    WalletRazorpayDepositConfirmSerializer,
    OnboardingSerializer,
)

# Custom function to add user info to token
from userauths.models import User
from api.serializers import UserSerializer

def get_tokens_for_user_with_userinfo(user):
    refresh = RefreshToken.for_user(user)
    # Only include selected fields in the user data (no onboardingStatus)
    user_data = {
        'id': user.id,
        'email': user.email,
        'user_type': user.user_type,
        'phone_number': user.phone_number,
        'is_active': user.is_active,
        'is_staff': user.is_staff,
        'date_joined': user.date_joined.isoformat() if user.date_joined else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
    }
    for token in (refresh, refresh.access_token):
        token['user'] = user_data
    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    }


class IsUserTypeAdmin(BasePermission):
    """
    Allows access only to users with user_type == 'Admin'.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and getattr(request.user, 'user_type', None) == 'Admin')

class UserRegistrationView(APIView):
    """
    User registration endpoint
    """
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Register a new user",
        request_body=UserRegistrationSerializer,
        responses={
            201: openapi.Response(
                description="User created successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'user': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'email': openapi.Schema(type=openapi.TYPE_STRING),
                                'user_type': openapi.Schema(type=openapi.TYPE_STRING),
                                'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING),
                                'is_active': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'is_staff': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'date_joined': openapi.Schema(type=openapi.TYPE_STRING),
                                'last_login': openapi.Schema(type=openapi.TYPE_STRING),
                            }
                        ),
                    }
                )
            ),
            400: "Bad Request - Invalid data"
        }
    )
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'message': 'User registered successfully',
                'user': UserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    """
    User login endpoint
    """
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Login user with email and password",
        request_body=UserLoginSerializer,
        responses={
            200: openapi.Response(
                description="Login successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'tokens': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'access': openapi.Schema(type=openapi.TYPE_STRING),
                                'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                            }
                        )
                    }
                )
            ),
            401: "Invalid credentials"
        }
    )
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(request, email=email, password=password)
            if user:
                tokens = get_tokens_for_user_with_userinfo(user)
                # Save the refresh token to the user model
                user.refresh_token = tokens['refresh']
                user.save()
                return Response({
                    'message': 'Login successful',
                    'tokens': tokens
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Invalid credentials'
                }, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileRetrieveView(APIView):
    permission_classes = []  # Unauthenticated

    @swagger_auto_schema(
        operation_description="Get user profile by user_id",
        responses={
            200: openapi.Response(
                description="Profile retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'user': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'user_email': openapi.Schema(type=openapi.TYPE_STRING),
                        'image': openapi.Schema(type=openapi.TYPE_STRING),
                        'full_name': openapi.Schema(type=openapi.TYPE_STRING),
                        'country': openapi.Schema(type=openapi.TYPE_STRING),
                        'about': openapi.Schema(type=openapi.TYPE_STRING),
                        'date_of_birth': openapi.Schema(type=openapi.TYPE_STRING),
                        'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                        'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                        'gender': openapi.Schema(type=openapi.TYPE_STRING),
                        'age': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'user_type': openapi.Schema(type=openapi.TYPE_STRING),
                        'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                        'display_name': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            404: "Profile not found"
        }
    )
    def get(self, request, user_id):
        try:
            profile = UserProfile.objects.get(user__id=user_id)
            serializer = UserProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)

class UserProfileUpdateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update user profile by user_id. Uses OnboardingSerializer for validation and required fields.",
        request_body=OnboardingSerializer,
        responses={
            200: openapi.Response(description="Profile updated successfully", schema=OnboardingSerializer),
            400: "Bad Request",
            404: "Profile not found"
        }
    )
    def put(self, request, user_id):
        try:
            profile = UserProfile.objects.get(user__id=user_id)
            serializer = OnboardingSerializer(profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except UserProfile.DoesNotExist:
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)

class OnboardingView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Onboard user profile. Only allowed if onboardingStatus is False.",
        request_body=OnboardingSerializer,
        responses={
            200: openapi.Response(
                description="Onboarding successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'profile': openapi.Schema(type=openapi.TYPE_OBJECT),
                        'onboardingStatus': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    }
                )
            ),
            400: "Bad Request",
            403: "Onboarding already completed"
        }
    )
    def put(self, request):
        user = request.user
        if user.onboardingStatus:
            return Response({'error': 'Onboarding already completed.'}, status=status.HTTP_403_FORBIDDEN)
        try:
            profile = user.profile
        except UserProfile.DoesNotExist:
            return Response({'error': 'Profile not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = OnboardingSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            user.onboardingStatus = True
            user.save()
            return Response({
                'message': 'Onboarding successful',
                'profile': serializer.data,
                'onboardingStatus': user.onboardingStatus
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetView(APIView):
    """
    Password reset request
    """
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Request password reset",
        request_body=PasswordResetSerializer,
        responses={
            200: "Password reset email sent",
            400: "Bad Request"
        }
    )
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                # Generate OTP
                otp = ''.join(random.choices(string.digits, k=6))
                user.otp = otp
                user.save()
                # Send OTP email using custom template
                sent = send_otp_email(email, otp, context={'user': user})
                if sent:
                    return Response({
                        'message': 'Password reset email sent successfully'
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'error': 'Failed to send OTP email. Please try again.'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except User.DoesNotExist:
                return Response({
                    'error': 'User with this email does not exist'
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    """
    Password reset confirmation
    """
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Confirm password reset with OTP",
        request_body=PasswordResetConfirmSerializer,
        responses={
            200: "Password reset successful",
            400: "Bad Request"
        }
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']
            
            try:
                user = User.objects.get(email=email, otp=otp)
                
                # Validate new password
                try:
                    validate_password(new_password, user)
                except ValidationError as e:
                    return Response({
                        'error': e.messages
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Set new password and clear OTP
                user.set_password(new_password)
                user.otp = None
                user.save()
                
                return Response({
                    'message': 'Password reset successful'
                }, status=status.HTTP_200_OK)
                
            except User.DoesNotExist:
                return Response({
                    'error': 'Invalid email or OTP'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(APIView):
    """
    Change password for authenticated user
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Change user password",
        request_body=ChangePasswordSerializer,
        responses={
            200: "Password changed successfully",
            400: "Bad Request"
        }
    )
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            
            # Check old password
            if not user.check_password(old_password):
                return Response({
                    'error': 'Invalid old password'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate new password
            try:
                validate_password(new_password, user)
            except ValidationError as e:
                return Response({
                    'error': e.messages
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Set new password
            user.set_password(new_password)
            user.save()
            
            return Response({
                'message': 'Password changed successfully'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    """
    User logout
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Logout user",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING)
            }
        ),
        responses={
            200: "Logout successful",
            400: "Bad Request"
        }
    )
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            return Response({
                'message': 'Logout successful'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': 'Invalid token'
            }, status=status.HTTP_400_BAD_REQUEST)

class RefreshTokenView(APIView):
    """
    Refresh access token
    """
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Refresh access token",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING)
            }
        ),
        responses={
            200: openapi.Response(
                description="Token refreshed",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: "Invalid token"
        }
    )
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                return Response({
                    'access': str(token.access_token),
                    'refresh': str(token),
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Refresh token is required'
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': 'Invalid refresh token'
            }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
@swagger_auto_schema(
    operation_description="Get current user information",
    responses={
        200: openapi.Response(
            description="User information retrieved successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'email': openapi.Schema(type=openapi.TYPE_STRING),
                    'user_type': openapi.Schema(type=openapi.TYPE_STRING),
                    'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                    'is_active': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'date_joined': openapi.Schema(type=openapi.TYPE_STRING),
                    'last_login': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )
    }
)
def get_user_info(request):
    """
    Get current user information
    """
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

class MobileTokenGenerateOtpView(APIView):
    permission_classes = [permissions.AllowAny]
    @swagger_auto_schema(
        operation_description="Generate OTP for mobile login. Accepts phone_number as JSON.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='User phone number'),
            },
            required=['phone_number'],
        ),
        responses={
            200: openapi.Response(description="OTP sent to phone number"),
            400: "Invalid phone number",
        }
    )
    def post(self, request):
        phone_number = request.data.get('phone_number')
        if not phone_number:
            return Response({'error': 'phone_number is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            return Response({'error': 'No user found with this phone number.'}, status=status.HTTP_400_BAD_REQUEST)
        generated_otp = ''.join(random.choices(string.digits, k=6))
        user.otp = generated_otp
        user.save()
        sent = send_otp_sms(phone_number, generated_otp)
        if sent:
            return Response({'message': 'OTP sent to your phone number.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Failed to send OTP. Please try again.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MobileTokenObtainView(APIView):
    permission_classes = [permissions.AllowAny]
    @swagger_auto_schema(
        operation_description="Login for mobile: Accepts phone_number and otp as JSON.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='User phone number'),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP sent to phone', maxLength=6, minLength=6),
            },
            required=['phone_number', 'otp'],
        ),
        responses={
            200: openapi.Response(description="Login successful, tokens returned"),
            400: "Invalid input or OTP",
        }
    )
    def post(self, request):
        phone_number = request.data.get('phone_number')
        otp = request.data.get('otp')
        if not phone_number or not otp:
            return Response({'error': 'phone_number and otp are required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            return Response({'error': 'No user found with this phone number.'}, status=status.HTTP_400_BAD_REQUEST)
        if user.otp != otp:
            return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        user.otp = None
        user.save()
        tokens = get_tokens_for_user_with_userinfo(user)
        # Save the refresh token to the user model
        user.refresh_token = tokens['refresh']
        user.save()
        return Response({
            'message': 'Login successful',
            'tokens': tokens
        }, status=status.HTTP_200_OK)

class MobilePasswordResetView(APIView):
    permission_classes = [permissions.AllowAny]
    @swagger_auto_schema(
        operation_description="Request password reset for mobile: send phone_number to receive OTP via SMS.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='User phone number'),
            },
            required=['phone_number'],
        ),
        responses={
            200: openapi.Response(description="OTP sent to phone number"),
            400: "Invalid phone number",
        }
    )
    def post(self, request):
        serializer = MobilePasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.validated_data['phone_number']
        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            return Response({'error': 'No user found with this phone number.'}, status=status.HTTP_400_BAD_REQUEST)
        # Generate OTP and send via Twilio
        generated_otp = ''.join(random.choices(string.digits, k=6))
        user.otp = generated_otp
        user.save()
        sent = send_otp_sms(phone_number, generated_otp)
        if sent:
            return Response({'message': 'OTP sent to your phone number.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Failed to send OTP. Please try again.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MobilePasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]
    @swagger_auto_schema(
        operation_description="Confirm password reset for mobile: send phone_number, otp, new_password, new_password_confirm.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='User phone number'),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP sent to phone', maxLength=6, minLength=6),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New password', minLength=8),
                'new_password_confirm': openapi.Schema(type=openapi.TYPE_STRING, description='Confirm new password', minLength=8),
            },
            required=['phone_number', 'otp', 'new_password', 'new_password_confirm'],
        ),
        responses={
            200: openapi.Response(description="Password reset successful"),
            400: "Invalid input or OTP",
        }
    )
    def post(self, request):
        serializer = MobilePasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.validated_data['phone_number']
        otp = serializer.validated_data['otp']
        new_password = serializer.validated_data['new_password']
        try:
            user = User.objects.get(phone_number=phone_number, otp=otp)
        except User.DoesNotExist:
            return Response({'error': 'Invalid phone number or OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        # Validate new password
        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)
        # Set new password and clear OTP
        user.set_password(new_password)
        user.otp = None
        user.save()
        return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)

class MobileChangePasswordView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = MobileChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # Placeholder: implement OTP check and password change
        return Response({'detail': 'Mobile change password placeholder'}, status=status.HTTP_200_OK)

class WalletGenerateOtpView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Generate OTP for wallet creation. Sends OTP to the logged-in user's phone number.",
        responses={
            200: openapi.Response(description="OTP sent to phone number"),
            400: "No phone number on user profile",
            500: "Failed to send OTP"
        }
    )
    def post(self, request):
        user = request.user
        phone_number = user.phone_number
        if not phone_number:
            return Response({'error': 'No phone number associated with this user.'}, status=status.HTTP_400_BAD_REQUEST)
        # Generate OTP
        import random, string
        otp = ''.join(random.choices(string.digits, k=6))
        user.otp = otp
        user.save()
        sent = send_otp_sms(phone_number, otp)
        if sent:
            return Response({'message': 'OTP sent to your phone number.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Failed to send OTP. Please try again.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WalletCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Create a new wallet. Accepts JSON: { 'pin': '123456', 'confirm_pin': '123456', 'otp': 'xxxxxx' } (user is taken from the logged-in user)",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'pin': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit wallet PIN'),
                'confirm_pin': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit wallet PIN (confirm)'),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit OTP'),
            },
            required=['pin', 'confirm_pin', 'otp'],
        ),
        responses={
            201: openapi.Response(description="Wallet created successfully"),
            400: "Invalid input",
        }
    )
    def post(self, request):
        from core.models import Wallet
        data = request.data.copy()
        user = request.user
        # Validate OTP
        otp = data.get('otp')
        if not otp or user.otp != otp:
            return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        pin = data.get('pin')
        confirm_pin = data.get('confirm_pin')
        if not pin or not confirm_pin:
            return Response({'error': 'PIN and confirm PIN are required.'}, status=status.HTTP_400_BAD_REQUEST)
        if pin != confirm_pin:
            return Response({'error': 'PINs do not match.'}, status=status.HTTP_400_BAD_REQUEST)
        if not pin.isdigit() or len(pin) != 6:
            return Response({'error': 'PIN must be a 6-digit number.'}, status=status.HTTP_400_BAD_REQUEST)
        # Create wallet
        wallet = Wallet.objects.create(user=user, pin=pin)
        # Optionally clear OTP after use
        user.otp = None
        user.save()
        return Response({
            'message': 'Wallet created successfully',
            'wallet_id': wallet.wallet_id,
            'balance': str(wallet.balance),
            'status': wallet.status,
            'created_at': wallet.created_at,
        }, status=status.HTTP_201_CREATED)

class WalletDepositView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Deposit funds into a wallet. Accepts JSON: { 'wallet_id': '...', 'amount': 100, 'pin': '123456' }",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'wallet_id': openapi.Schema(type=openapi.TYPE_STRING, description='Wallet ID'),
                'amount': openapi.Schema(type=openapi.TYPE_NUMBER, description='Amount to deposit'),
                'pin': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit wallet PIN'),
            },
            required=['wallet_id', 'amount', 'pin'],
        ),
        responses={
            200: openapi.Response(description="Deposit successful"),
            400: "Invalid input",
        }
    )
    def post(self, request):
        serializer = WalletDepositSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        wallet_id = serializer.validated_data['wallet_id']
        amount = serializer.validated_data['amount']
        pin = serializer.validated_data['pin']
        try:
            wallet = Wallet.objects.get(wallet_id=wallet_id, user=request.user)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        if wallet.pin != pin:
            return Response({'error': 'Invalid wallet PIN.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            wallet.deposit(amount)
            Transaction.objects.create(
                wallet=wallet,
                amount=amount,
                transaction_type='deposit',
                status='completed',
                description='Deposit to wallet',
            )
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'message': 'Deposit successful', 'balance': str(wallet.balance)}, status=status.HTTP_200_OK)

class WalletWithdrawView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Withdraw funds from a wallet. Accepts JSON: { 'wallet_id': '...', 'amount': 50, 'pin': '123456' }",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'wallet_id': openapi.Schema(type=openapi.TYPE_STRING, description='Wallet ID'),
                'amount': openapi.Schema(type=openapi.TYPE_NUMBER, description='Amount to withdraw'),
                'pin': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit wallet PIN'),
            },
            required=['wallet_id', 'amount', 'pin'],
        ),
        responses={
            200: openapi.Response(description="Withdrawal successful"),
            400: "Invalid input",
        }
    )
    def post(self, request):
        serializer = WalletWithdrawSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        wallet_id = serializer.validated_data['wallet_id']
        amount = serializer.validated_data['amount']
        pin = serializer.validated_data['pin']
        try:
            wallet = Wallet.objects.get(wallet_id=wallet_id, user=request.user)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        if wallet.pin != pin:
            return Response({'error': 'Invalid wallet PIN.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            wallet.withdraw(amount)
            Transaction.objects.create(
                wallet=wallet,
                amount=amount,
                transaction_type='withdraw',
                status='completed',
                description='Withdraw from wallet',
            )
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'message': 'Withdrawal successful', 'balance': str(wallet.balance)}, status=status.HTTP_200_OK)

class WalletTransactionListView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    @swagger_auto_schema(
        operation_description="List recent transactions for a wallet. Accepts query param: wallet_id=...",
        manual_parameters=[
            openapi.Parameter('wallet_id', openapi.IN_QUERY, description="Wallet ID", type=openapi.TYPE_STRING, required=True),
        ],
        responses={
            200: openapi.Response(description="List of recent transactions"),
            400: "Invalid input",
        }
    )
    def get(self, request):
        wallet_id = request.query_params.get('wallet_id')
        if not wallet_id:
            return Response({'error': 'wallet_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            wallet = Wallet.objects.get(wallet_id=wallet_id, user=request.user)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        transactions = wallet.transactions.order_by('-created_at')[:20]
        data = [
            {
                'amount': str(tx.amount),
                'transaction_type': tx.transaction_type,
                'status': tx.status,
                'reference': tx.reference,
                'description': tx.description,
                'created_at': tx.created_at,
            }
            for tx in transactions
        ]
        return Response({'transactions': data}, status=status.HTTP_200_OK)

class WalletBalanceView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Check wallet balance. Accepts query params: wallet_id=...&pin=123456",
        manual_parameters=[
            openapi.Parameter('wallet_id', openapi.IN_QUERY, description="Wallet ID", type=openapi.TYPE_STRING, required=True),
            openapi.Parameter('pin', openapi.IN_QUERY, description="6-digit wallet PIN", type=openapi.TYPE_STRING, required=True),
        ],
        responses={
            200: openapi.Response(description="Wallet balance returned"),
            400: "Invalid input",
        }
    )
    def get(self, request):
        serializer = WalletBalanceSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        wallet_id = serializer.validated_data['wallet_id']
        pin = serializer.validated_data['pin']
        try:
            wallet = Wallet.objects.get(wallet_id=wallet_id, user=request.user)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        if wallet.pin != pin:
            return Response({'error': 'Invalid wallet PIN.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'balance': str(wallet.balance), 'status': wallet.status}, status=status.HTTP_200_OK)

class WalletRazorpayDepositInitiateView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Initiate a Razorpay deposit. Accepts JSON: { 'wallet_id': '...', 'amount': 100, 'pin': '123456' }",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'wallet_id': openapi.Schema(type=openapi.TYPE_STRING, description='Wallet ID'),
                'amount': openapi.Schema(type=openapi.TYPE_NUMBER, description='Amount to deposit'),
                'pin': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit wallet PIN'),
            },
            required=['wallet_id', 'amount', 'pin'],
        ),
        responses={
            200: openapi.Response(description="Razorpay order created"),
            400: "Invalid input",
        }
    )
    def post(self, request):
        serializer = WalletRazorpayDepositInitiateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        wallet_id = serializer.validated_data['wallet_id']
        amount = serializer.validated_data['amount']
        pin = serializer.validated_data['pin']
        try:
            wallet = Wallet.objects.get(wallet_id=wallet_id, user=request.user)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        if wallet.pin != pin:
            return Response({'error': 'Invalid wallet PIN.'}, status=status.HTTP_400_BAD_REQUEST)
        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        order_data = {
            'amount': int(amount * 100),  # Razorpay expects paise
            'currency': 'INR',
            'receipt': f'wallet_{wallet.wallet_id}_{wallet.user.id}',
            'payment_capture': 1,
        }
        order = client.order.create(data=order_data)
        return Response({
            'order_id': order['id'],
            'amount': order['amount'],
            'currency': order['currency'],
            'wallet_id': wallet.wallet_id,
            'razorpay_key_id': settings.RAZORPAY_KEY_ID,
        }, status=status.HTTP_200_OK)

class WalletRazorpayDepositConfirmView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Confirm a Razorpay deposit. Accepts JSON: { 'wallet_id': '...', 'payment_id': '...', 'order_id': '...', 'signature': '...' }",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'wallet_id': openapi.Schema(type=openapi.TYPE_STRING, description='Wallet ID'),
                'payment_id': openapi.Schema(type=openapi.TYPE_STRING, description='Razorpay payment ID'),
                'order_id': openapi.Schema(type=openapi.TYPE_STRING, description='Razorpay order ID'),
                'signature': openapi.Schema(type=openapi.TYPE_STRING, description='Razorpay signature'),
            },
            required=['wallet_id', 'payment_id', 'order_id', 'signature'],
        ),
        responses={
            200: openapi.Response(description="Deposit confirmed and wallet credited"),
            400: "Invalid input or payment verification failed",
        }
    )
    def post(self, request):
        serializer = WalletRazorpayDepositConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        wallet_id = serializer.validated_data['wallet_id']
        payment_id = serializer.validated_data['payment_id']
        order_id = serializer.validated_data['order_id']
        signature = serializer.validated_data['signature']
        try:
            wallet = Wallet.objects.get(wallet_id=wallet_id, user=request.user)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)
        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        try:
            client.utility.verify_payment_signature({
                'razorpay_order_id': order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature,
            })
        except razorpay.errors.SignatureVerificationError:
            return Response({'error': 'Payment signature verification failed.'}, status=status.HTTP_400_BAD_REQUEST)
        # Fetch payment to get amount
        payment = client.payment.fetch(payment_id)
        amount = int(payment['amount']) / 100  # Convert paise to rupees/points
        wallet.deposit(amount)
        Transaction.objects.create(
            wallet=wallet,
            amount=amount,
            transaction_type='deposit',
            status='completed',
            description=f'Razorpay deposit, payment_id: {payment_id}',
        )
        return Response({'message': 'Deposit successful', 'balance': str(wallet.balance)}, status=status.HTTP_200_OK)

class GetWalletIdView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get the wallet_id of the logged-in user.",
        responses={
            200: openapi.Response(
                description="Wallet ID returned",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'wallet_id': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            404: "Wallet not found"
        }
    )
    def get(self, request):
        user = request.user
        from core.models import Wallet
        try:
            wallet = Wallet.objects.get(user=user)
            return Response({'wallet_id': wallet.wallet_id}, status=status.HTTP_200_OK)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND)

class EventListView(generics.ListAPIView):
    queryset = Event.objects.all().order_by('-start_datetime')
    serializer_class = EventSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="List all events. Publicly accessible.",
        responses={
            200: openapi.Response(
                description="List of events",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_OBJECT)
                )
            )
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

class EventCreateView(generics.CreateAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [IsUserTypeAdmin]

    @swagger_auto_schema(
        operation_description="Create a new event. Admin user_type only.",
        request_body=EventSerializer,
        responses={
            201: openapi.Response(description="Event created successfully", schema=EventSerializer),
            400: "Invalid input"
        }
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

class EventRSVPCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Register (RSVP) for an event. Only 'confirmed' status is allowed. User must provide wallet PIN. Deducts token_cost from user wallet and credits to event creator's wallet. Returns QR code on success.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'status': openapi.Schema(type=openapi.TYPE_STRING, description="RSVP status (must be 'confirmed' for registration)"),
                'pin': openapi.Schema(type=openapi.TYPE_STRING, description="6-digit wallet PIN"),
            },
            required=['status', 'pin']
        ),
        responses={
            200: openapi.Response(description="RSVP created and QR code returned"),
            400: "Invalid input, insufficient balance, or wrong PIN"
        }
    )
    def post(self, request, event_id):
        event = generics.get_object_or_404(Event, id=event_id)
        status_val = request.data.get('status', 'confirmed')
        pin = request.data.get('pin')
        if status_val != 'confirmed':
            return Response({'error': "Only 'confirmed' status is allowed for registration."}, status=status.HTTP_400_BAD_REQUEST)
        if EventRSVP.objects.filter(user=request.user, event=event, status='confirmed').exists():
            return Response({'error': 'You have already registered for this event.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user_wallet = Wallet.objects.get(user=request.user)
        except Wallet.DoesNotExist:
            return Response({'error': 'User wallet not found.'}, status=status.HTTP_400_BAD_REQUEST)
        if not pin or user_wallet.pin != pin:
            return Response({'error': 'Invalid wallet PIN.'}, status=status.HTTP_400_BAD_REQUEST)
        if user_wallet.balance < event.token_cost:
            return Response({'error': 'Insufficient wallet balance.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            admin_wallet = Wallet.objects.get(user=event.created_by)
        except Wallet.DoesNotExist:
            return Response({'error': 'Admin wallet not found.'}, status=status.HTTP_400_BAD_REQUEST)
        user_wallet.withdraw(event.token_cost)
        admin_wallet.deposit(event.token_cost)
        Transaction.objects.create(
            wallet=user_wallet,
            amount=event.token_cost,
            transaction_type='withdraw',
            status='completed',
            description=f'Event registration for {event.title}',
        )
        Transaction.objects.create(
            wallet=admin_wallet,
            amount=event.token_cost,
            transaction_type='deposit',
            status='completed',
            description=f'Received event registration for {event.title}',
        )
        rsvp = EventRSVP.objects.create(user=request.user, event=event, status='confirmed')
        qr_data = {
            'event_id': event.id,
            'event_title': event.title,
            'user_id': request.user.id,
            'rsvp_id': rsvp.id,
            'status': rsvp.status,
        }
        qr_json = json.dumps(qr_data)
        qr_img = qrcode.make(qr_json)
        buf = io.BytesIO()
        qr_img.save(buf, format='PNG')
        buf.seek(0)
        qr_base64 = base64.b64encode(buf.read()).decode('utf-8')
        return Response({
            'event': EventSerializer(event).data,
            'rsvp': EventRSVPSerializer(rsvp).data,
            'qr_code_base64': qr_base64,
        }, status=status.HTTP_200_OK)

class EventRSVPUpdateView(APIView):
    permission_classes = [IsUserTypeAdmin]

    @swagger_auto_schema(
        operation_description="Update RSVP status to 'attended'. Only accessible by admin. Expects the full QR JSON as sent in RSVP create.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'qr_json': openapi.Schema(type=openapi.TYPE_STRING, description="QR JSON string from RSVP create response"),
                'status': openapi.Schema(type=openapi.TYPE_STRING, description="RSVP status (must be 'attended')"),
            },
            required=['qr_json', 'status']
        ),
        responses={
            200: openapi.Response(description="RSVP status updated", schema=EventRSVPSerializer),
            400: "Invalid input or not allowed"
        }
    )
    def post(self, request):
        qr_json = request.data.get('qr_json')
        status_val = request.data.get('status', 'attended')
        if not qr_json:
            return Response({'error': 'QR JSON is required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            qr_data = json.loads(qr_json)
            rsvp_id = qr_data.get('rsvp_id')
        except Exception:
            return Response({'error': 'Invalid QR JSON.'}, status=status.HTTP_400_BAD_REQUEST)
        if not rsvp_id:
            return Response({'error': 'RSVP ID missing in QR JSON.'}, status=status.HTTP_400_BAD_REQUEST)
        if status_val != 'attended':
            return Response({'error': "Only 'attended' status update is allowed here."}, status=status.HTTP_400_BAD_REQUEST)
        rsvp = generics.get_object_or_404(EventRSVP, id=rsvp_id)
        rsvp.status = 'attended'
        rsvp.attended_at = timezone.now()
        rsvp.save()
        return Response(EventRSVPSerializer(rsvp).data, status=status.HTTP_200_OK)

class EventRSVPListView(generics.ListAPIView):
    serializer_class = EventRSVPSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = EventRSVP.objects.all()

    @swagger_auto_schema(
        operation_description="List RSVPs. Filter by event_id or user_id as query params. Authenticated users only. Each RSVP includes QR data and QR code base64.",
        manual_parameters=[
            openapi.Parameter('event_id', openapi.IN_QUERY, description="Event ID to filter RSVPs", type=openapi.TYPE_INTEGER),
            openapi.Parameter('user_id', openapi.IN_QUERY, description="User ID to filter RSVPs", type=openapi.TYPE_INTEGER),
        ],
        responses={
            200: openapi.Response(
                description="List of RSVPs with QR data and QR code base64",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_OBJECT)
                )
            )
        }
    )
    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        event_id = request.query_params.get('event_id')
        user_id = request.query_params.get('user_id')
        if event_id:
            queryset = queryset.filter(event__id=event_id)
        if user_id:
            queryset = queryset.filter(user__id=user_id)
        data = []
        for rsvp in queryset:
            event = rsvp.event
            qr_data = {
                'event_id': event.id,
                'event_title': event.title,
                'user_id': rsvp.user.id,
                'rsvp_id': rsvp.id,
                'status': rsvp.status,
            }
            # Generate QR code base64
            qr_json = json.dumps(qr_data)
            qr_img = qrcode.make(qr_json)
            buf = io.BytesIO()
            qr_img.save(buf, format='PNG')
            buf.seek(0)
            qr_code_base64 = base64.b64encode(buf.read()).decode('utf-8')
            rsvp_data = EventRSVPSerializer(rsvp).data
            rsvp_data['qr_data'] = qr_data
            rsvp_data['qr_code_base64'] = qr_code_base64
            rsvp_data['event'] = EventSerializer(event).data
            data.append(rsvp_data)
        return Response(data, status=status.HTTP_200_OK)

class CheckOnboardingStatusView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Check onboarding status of the logged-in user.",
        responses={
            200: openapi.Response(
                description="Onboarding status returned",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'onboardingStatus': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    }
                )
            )
        }
    )
    def get(self, request):
        return Response({'onboardingStatus': request.user.onboardingStatus}, status=status.HTTP_200_OK)

class ProcessEventRewardsView(APIView):
    permission_classes = [IsUserTypeAdmin]

    @swagger_auto_schema(
        operation_description="Process rewards and no-shows for a specific event. Admin only.",
        responses={
            200: openapi.Response(description="Rewards processed and no-shows updated."),
            404: "Event not found"
        }
    )
    def post(self, request, event_id):
        event = generics.get_object_or_404(Event, id=event_id)
        # Process no-shows
        confirmed_rsvps = EventRSVP.objects.filter(event=event, status='confirmed')
        for rsvp in confirmed_rsvps:
            rsvp.status = 'no show'
            rsvp.save()
        # Process rewards
        attended_rsvps = EventRSVP.objects.filter(event=event, status='attended')
        for rsvp in attended_rsvps:
            try:
                wallet = Wallet.objects.get(user=rsvp.user)
                wallet.deposit(event.token_reward)
                Transaction.objects.create(
                    wallet=wallet,
                    amount=event.token_reward,
                    transaction_type='deposit',
                    status='completed',
                    description=f'Reward for attending event {event.title}',
                )
            except Wallet.DoesNotExist:
                pass
        return Response({'message': 'Rewards processed and no-shows updated.'}, status=status.HTTP_200_OK)

