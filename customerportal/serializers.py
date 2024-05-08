from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import *
from django.contrib.auth import get_user_model

User = get_user_model()

class CustomerRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'username', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True},
            'confirm_password': {'write_only': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True},
            'username': {'required': True},
        }

    def validate(self, data):
        if data['password'] != data.pop('confirm_password'):
            raise serializers.ValidationError("Passwords do not match.")

        password = data['password']
        try:
            # Validate password complexity and length
            validate_password(password)

        except ValidationError as e:
            raise serializers.ValidationError(str(e))

        return data

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(password=password, **validated_data)
        return user

def create(self, validated_data):
    # Remove confirm_password from validated_data if present
    confirm_password = validated_data.pop('confirm_password', None)

    # Check if confirm_password is present and matches the password
    if confirm_password is None or confirm_password != validated_data['password']:
        raise serializers.ValidationError("Passwords do not match.")

    email = validated_data['email']
    if User.objects.filter(email=email).exists():
        raise serializers.ValidationError("Email already taken. Please try another one.")
    else:
        user = User.objects.create_user(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user



class CustomerLoginSerializer(serializers.Serializer):
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


class PasswordResetSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)



class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Savings
        fields = ['id', 'balance', 'account_type']


class DepositSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=15, decimal_places=2)
    description = serializers.CharField(required=False, allow_blank=True)  # Description field added to the serializer

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero.")
        return value

class WithdrawalSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=15, decimal_places=2)
    description = models.TextField(blank=True)  # Add a description field


    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero.")
        return value
    

class SavingsTransactionSerializer(serializers.ModelSerializer):
    account_id = serializers.PrimaryKeyRelatedField(source='account', read_only=True)

    class Meta:
        model = SavingsTransaction
        fields = ['account_id', 'transaction_type', 'amount', 'date']

class CurrentTransactionSerializer(serializers.ModelSerializer):
    account_id = serializers.PrimaryKeyRelatedField(source='account', read_only=True)

    class Meta:
        model = CurrentTransaction
        fields = ['account_id', 'transaction_type', 'amount', 'date']


class FixedDepositSerializer(serializers.ModelSerializer):
    total_amount = serializers.DecimalField(max_digits=15, decimal_places=2, read_only=True)
    end_date = serializers.DateField(read_only=True)

    class Meta:
        model = FixedDeposit
        fields = ['id', 'amount', 'duration_months', 'total_amount', 'end_date']

    def validate_amount(self, value):
        if value < 5000:
            raise serializers.ValidationError("Amount must be greater than 5000.")
        return value

    def validate_duration_months(self, value):
        if value <= 0:
            raise serializers.ValidationError("Duration must be a positive integer.")
        return value
    
    
class RecurrentDepositSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecurrentDeposit
        fields = ['id',  'amount', 'frequency', 'created_at', 'total_amount', 'end_date']
    
    def validate_amount(self, value):
        if value < 500:
            raise serializers.ValidationError("Amount must be greater than 500.")
        return value
    
    

class FundTransferSerializer(serializers.ModelSerializer):
    class Meta:
        model = FundTransfer
        fields = ['sender_account_number', 'receiver_account_number', 'amount', 'timestamp']



    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be a positive number")
        return value
    def get_account_type(self, obj):
        # Retrieve the account type of the sender's account
        try:
            sender_account = Savings.objects.get(account_number=obj.sender_account_number)
            return sender_account.account_type
        except Savings.DoesNotExist:
            return None

class LoanApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoanApplication
        fields = ['loan_type', 'amount', 'duration_months', 'status', 'applied_date']
    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Loan amount must be greater than zero.")
        elif value < 5000:
            raise serializers.ValidationError("Loan amount must be at least 5000.")
        return value

    def validate_duration_months(self, value):
        if value <= 0:
            raise serializers.ValidationError("Loan duration must be greater than zero.")
        return value



class ReviewRatingDbSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReviewRatingDb
        fields = '__all__'


class CustomerMessagesSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerMessages
        fields = '__all__'

class ExpenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Expense
        fields = ['id', 'category_name', 'amount', 'description', 'date']

class BudgetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Budget
        fields = ['id', 'category_name', 'account_number', 'alloted_budget', 'balance_budget', 'start_date', 'end_date']
    def validate(self, data):
        alloted_budget = data.get('alloted_budget')
        balance_budget = data.get('balance_budget')

        if alloted_budget < balance_budget:
            raise serializers.ValidationError("Alloted budget must be greater than balance budget.")

        return data

class SavingsGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = SavingsGoal
        fields = ['id', 'goal_name', 'target_amount', 'current_amount', 'completed']