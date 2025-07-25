from rest_framework import serializers

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from userauths.models import User, UserProfile
from core.models import Wallet, Event, EventRSVP

class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    class Meta:
        model = User
        fields = [
            'id', 'email', 'user_type', 'phone_number', 'refresh_token',
            'is_active', 'is_staff', 'date_joined', 'last_login'
        ]
        read_only_fields = ['id', 'is_active', 'is_staff', 'date_joined', 'last_login']

class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = [
            'email', 'user_type', 'phone_number', 'password', 'password_confirm'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'password_confirm': {'write_only': True}
        }
    
    def validate_email(self, value):
        """Validate email uniqueness"""
        if User.objects.filter(email=value.lower()).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value.lower()
    
    def validate_password(self, value):
        """Validate password strength"""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value
    
    def validate(self, attrs):
        """Validate password confirmation"""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs
    
    def create(self, validated_data):
        """Create user with validated data"""
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        if user.user_type == 'admin':
            user.onboardingStatus = True
            user.save()
        return user

class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate_email(self, value):
        """Validate email format"""
        return value.lower()

class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for UserProfile model"""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    display_name = serializers.ReadOnlyField()
    
    class Meta:
        model = UserProfile
        fields = [
            'id', 'user', 'user_email', 'image', 'full_name',
            'country', 'about', 'date_of_birth', 'gender', 'age', 'user_type', 'phone_number', 'display_name',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'user', 'user_email', 'display_name', 'created_at', 'updated_at', 'user_type', 'phone_number']
    
    def validate_image(self, value):
        """Validate image file"""
        if value:
            # Check file size (5MB limit)
            if value.size > 5 * 1024 * 1024:
                raise serializers.ValidationError("Image file size must be less than 5MB.")
            
            # Check file type
            allowed_types = ['image/jpeg', 'image/png', 'image/gif']
            if value.content_type not in allowed_types:
                raise serializers.ValidationError("Only JPEG, PNG and GIF images are allowed.")
        
        return value
    
    def validate_age(self, value):
        """Validate age"""
        if value and (value < 0 or value > 150):
            raise serializers.ValidationError("Age must be between 0 and 150.")
        return value

class PasswordResetSerializer(serializers.Serializer):
    """Serializer for password reset request"""
    email = serializers.EmailField()
    
    def validate_email(self, value):
        """Validate email exists"""
        if not User.objects.filter(email=value.lower()).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value.lower()

class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation"""
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(min_length=8, write_only=True)
    new_password_confirm = serializers.CharField(min_length=8, write_only=True)
    
    def validate_email(self, value):
        """Validate email format"""
        return value.lower()
    
    def validate_otp(self, value):
        """Validate OTP format"""
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only digits.")
        return value
    
    def validate_new_password(self, value):
        """Validate new password strength"""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value
    
    def validate(self, attrs):
        """Validate password confirmation"""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs

class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing password"""
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(min_length=8, write_only=True)
    new_password_confirm = serializers.CharField(min_length=8, write_only=True)
    
    def validate_old_password(self, value):
        """Validate old password"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Invalid old password.")
        return value
    
    def validate_new_password(self, value):
        """Validate new password strength"""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value
    
    def validate(self, attrs):
        """Validate password confirmation"""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs

class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile (partial updates)"""
    
    class Meta:
        model = UserProfile
        fields = [
            'image', 'full_name', 'country', 'about', 'date_of_birth',
            'first_name', 'last_name', 'gender', 'age', 'user_type', 'phone_number'
        ]
    
    def validate_image(self, value):
        """Validate image file"""
        if value:
            # Check file size (5MB limit)
            if value.size > 5 * 1024 * 1024:
                raise serializers.ValidationError("Image file size must be less than 5MB.")
            
            # Check file type
            allowed_types = ['image/jpeg', 'image/png', 'image/gif']
            if value.content_type not in allowed_types:
                raise serializers.ValidationError("Only JPEG, PNG and GIF images are allowed.")
        
        return value
    
    def validate_age(self, value):
        """Validate age"""
        if value and (value < 0 or value > 150):
            raise serializers.ValidationError("Age must be between 0 and 150.")
        return value

class UserListSerializer(serializers.ModelSerializer):
    """Serializer for listing users (public info only)"""
    full_name = serializers.ReadOnlyField()
    profile_image = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'email', 'user_type', 'profile_image']
    
    def get_profile_image(self, obj):
        """Get profile image URL if available"""
        try:
            if obj.profile.image:
                return self.context['request'].build_absolute_uri(obj.profile.image.url)
        except UserProfile.DoesNotExist:
            pass
        return None 

class MobileTokenObtainSerializer(serializers.Serializer):
    phone_number = serializers.CharField()
    otp = serializers.CharField(required=False, max_length=6, min_length=6)

    def validate_phone_number(self, value):
        if not User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("No user found with this phone number.")
        return value

class MobilePasswordResetSerializer(serializers.Serializer):
    phone_number = serializers.CharField()

    def validate_phone_number(self, value):
        if not User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("No user found with this phone number.")
        return value

class MobilePasswordResetConfirmSerializer(serializers.Serializer):
    phone_number = serializers.CharField()
    otp = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(min_length=8, write_only=True)
    new_password_confirm = serializers.CharField(min_length=8, write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs

class MobileChangePasswordSerializer(serializers.Serializer):
    phone_number = serializers.CharField()
    otp = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(min_length=8, write_only=True)
    new_password_confirm = serializers.CharField(min_length=8, write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs 

class WalletGenerateOtpSerializer(serializers.Serializer):
    phone_number = serializers.CharField()

    def validate_phone_number(self, value):
        from userauths.models import User
        if not User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError('No user found with this phone number.')
        return value

class WalletCreateSerializer(serializers.Serializer):
    user = serializers.CharField()
    pin = serializers.CharField(min_length=6, max_length=6)
    confirm_pin = serializers.CharField(min_length=6, max_length=6)
    otp = serializers.CharField(max_length=6, min_length=6)

    def validate(self, attrs):
        user_value = attrs.get('user')
        otp = attrs.get('otp')
        pin = attrs.get('pin')
        confirm_pin = attrs.get('confirm_pin')
        from userauths.models import User
        user = None
        if user_value.isdigit():
            user = User.objects.filter(id=user_value).first()
        else:
            user = User.objects.filter(email=user_value.lower()).first()
        if not user:
            raise serializers.ValidationError('User not found.')
        if not otp or user.otp != otp:
            raise serializers.ValidationError('Invalid OTP.')
        if pin != confirm_pin:
            raise serializers.ValidationError('PINs do not match.')
        attrs['user_obj'] = user
        return attrs

    def validate_pin(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError('PIN must be a 6-digit number.')
        return value

class WalletDepositSerializer(serializers.Serializer):
    wallet_id = serializers.CharField()
    amount = serializers.DecimalField(max_digits=20, decimal_places=2)
    pin = serializers.CharField(min_length=6, max_length=6)

class WalletWithdrawSerializer(serializers.Serializer):
    wallet_id = serializers.CharField()
    amount = serializers.DecimalField(max_digits=20, decimal_places=2)
    pin = serializers.CharField(min_length=6, max_length=6)

class WalletBalanceSerializer(serializers.Serializer):
    wallet_id = serializers.CharField()
    pin = serializers.CharField(min_length=6, max_length=6) 

class WalletRazorpayDepositInitiateSerializer(serializers.Serializer):
    wallet_id = serializers.CharField()
    amount = serializers.DecimalField(max_digits=20, decimal_places=2)
    pin = serializers.CharField(min_length=6, max_length=6)

class WalletRazorpayDepositConfirmSerializer(serializers.Serializer):
    wallet_id = serializers.CharField()
    payment_id = serializers.CharField()
    order_id = serializers.CharField()
    signature = serializers.CharField() 

class OnboardingSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = [
            'image', 'full_name', 'country', 'about', 'date_of_birth', 'gender', 'age'
        ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['full_name'].required = True
        self.fields['image'].required = True
        self.fields['date_of_birth'].required = True
        self.fields['gender'].required = True
        self.fields['country'].required = True
        self.fields['about'].required = True
        self.fields['age'].required = True 

class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = '__all__'

class EventRSVPSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventRSVP
        fields = '__all__' 

class WalletSpendSerializer(serializers.Serializer):
    wallet_id = serializers.CharField()
    amount = serializers.DecimalField(max_digits=20, decimal_places=2)
    pin = serializers.CharField(min_length=6, max_length=6)

class WalletReceiveSerializer(serializers.Serializer):
    wallet_id = serializers.CharField()
    amount = serializers.DecimalField(max_digits=20, decimal_places=2)
    pin = serializers.CharField(min_length=6, max_length=6) 

class WalletTransferSerializer(serializers.Serializer):
    sender_wallet_id = serializers.CharField()
    receiver_wallet_id = serializers.CharField()
    amount = serializers.DecimalField(max_digits=20, decimal_places=2)
    pin = serializers.CharField(min_length=6, max_length=6) 