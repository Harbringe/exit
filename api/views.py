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
from core.models import Wallet, Transaction
import razorpay

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
    user_data = UserSerializer(user).data
    user_data['onboardingStatus'] = user.onboardingStatus
    # Add user info to both tokens
    for token in (refresh, refresh.access_token):
        token['user'] = user_data
    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    }

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
                return Response({
                    'message': 'Login successful',
                    'tokens': tokens
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Invalid credentials'
                }, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    """
    User profile management
    """
    # permission_classes = [permissions.IsAuthenticated]
    permission_classes = []
    
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

    @swagger_auto_schema(
        operation_description="Update user profile by user_id",
        request_body=UserProfileSerializer,
        responses={
            200: openapi.Response(
                description="Profile updated successfully",
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
            400: "Bad Request",
            404: "Profile not found"
        }
    )
    def put(self, request, user_id):
        try:
            profile = UserProfile.objects.get(user__id=user_id)
            serializer = UserProfileSerializer(profile, data=request.data, partial=True)
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
    @swagger_auto_schema(
        operation_description="Generate OTP for wallet creation. Accepts JSON: { 'phone_number': '...' }",
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
        serializer = WalletGenerateOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.validated_data['phone_number']
        from userauths.models import User
        user = User.objects.get(phone_number=phone_number)
        # Generate OTP
        import random, string
        otp = ''.join(random.choices(string.digits, k=6))
        user.otp = otp
        user.save()
        # Optionally: Save OTP in a temp Wallet object (not created yet, so just keep in user)
        sent = send_otp_sms(phone_number, otp)
        if sent:
            return Response({'message': 'OTP sent to your phone number.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Failed to send OTP. Please try again.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WalletCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Create a new wallet. Accepts JSON: { 'user': 'id or email', 'pin': '123456', 'confirm_pin': '123456', 'otp': 'xxxxxx' }",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'user': openapi.Schema(type=openapi.TYPE_STRING, description='User ID or email'),
                'pin': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit wallet PIN'),
                'confirm_pin': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit wallet PIN (confirm)'),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='6-digit OTP'),
            },
            required=['user', 'pin', 'confirm_pin', 'otp'],
        ),
        responses={
            201: openapi.Response(description="Wallet created successfully"),
            400: "Invalid input",
        }
    )
    def post(self, request):
        serializer = WalletCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user_obj']
        pin = serializer.validated_data['pin']
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
