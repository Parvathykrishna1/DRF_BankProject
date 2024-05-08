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
        extra_kwargs = {'first_name': {'required': True},
                        'last_name': {'required': True},
                        'email': {'required': True},
                        'username': {'required': True},
                        'password': {'write_only': True, 'required': True}
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


class InterestRateSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoanInterestRate
        fields = ['loan_type', 'rate'] 

class LoanApprovalSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoanApproval
        fields = ['loan_application', 'new_status']


class BankNewsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankNews
        fields = '__all__'

