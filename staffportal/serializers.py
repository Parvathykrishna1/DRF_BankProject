from django.forms import ValidationError
from rest_framework import serializers
from staffportal.models import BankAccount, BankNews, CustomUser, FDAndRDInterestRate, LoanApproval, LoanInterestRate
from django.contrib.auth.password_validation import validate_password


class RegisterNewAdminSerializer(serializers.ModelSerializer):
    is_superuser = serializers.BooleanField(default=False, read_only=True)
    is_staff = serializers.BooleanField(default=False, read_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'username', 'password', 'confirm_password', 'is_superuser', 'is_staff']
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True, 'error_messages': {'required': 'Email is required.'}},
            'username': {'required': True, 'error_messages': {'required': 'Username is required.'}},
            'password': {'write_only': True, 'required': True, 'error_messages': {'required': 'Password is required.'}}
        }

    def validate(self, data):
        if data['password'] != data.pop('confirm_password'):
            raise serializers.ValidationError("Passwords do not match.")

        # Validate password complexity and length
        password = data['password']
        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))

        return data

    def validate_password(self, value):
        # Minimum password length
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")

        # Check if password contains uppercase, lowercase, and digits
        if not any(char.isupper() for char in value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not any(char.islower() for char in value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError("Password must contain at least one digit.")

        return value

    def create(self, validated_data):
        email = validated_data['email']
        username = validated_data['username']
        if CustomUser.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email already taken. Please try another one.")
        elif CustomUser.objects.filter(username=username).exists():
            raise serializers.ValidationError("Username already taken. Please try another one.")
        else:
            user = CustomUser.objects.create_superuser(**validated_data)
            user.set_password(validated_data['password'])
            user.save()
            return user




class StaffLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        # Validate email and password fields
        if not email:
            raise serializers.ValidationError("Email is required.")
        if not password:
            raise serializers.ValidationError("Password is required.")

        return data


class BankAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankAccount
        fields = '__all__'


class FDAndRDInterestRateSerializer(serializers.ModelSerializer):
    class Meta:
        model = FDAndRDInterestRate
        fields = ['id', 'rate']


class LoanInterestRateInterestRateSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoanInterestRate
        fields = ['loan_type', 'rate'] 


class BankNewsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankNews
        fields = '__all__'

