from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework.validators import UniqueValidator
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
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True, 'error_messages': {'required': 'Email is required.'}},
            'username': {'required': True, 'error_messages': {'required': 'Username is required.'}},
            'password': {'write_only': True, 'required': True, 'error_messages': {'required': 'Password is required.'}}
        }

    def validate(self, data):
        if 'password' in data and 'confirm_password' in data:
            if data['password'] != data.pop('confirm_password'):
                raise serializers.ValidationError("Passwords do not match.")

            password = data['password']
            try:
                self.validate_password(password)
            except serializers.ValidationError as e:
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
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email already taken. Please try another one.")
        elif User.objects.filter(username=username).exists():
            raise serializers.ValidationError("Username already taken. Please try another one.")
        else:
            user = User.objects.create_superuser(**validated_data)
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

    def validate_new_password(self, value):
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

        # Perform additional password validations using Django's built-in validators
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))

        return value

    def validate(self, data):
        if data['new_password'] == data['old_password']:
            raise serializers.ValidationError("New password cannot be the same as the old password.")

        return data



class AccountSerializer(serializers.ModelSerializer):
    aadhar_number = serializers.CharField(max_length=12)
    phone_number = serializers.CharField(max_length=10)

    class Meta:
        model = Savings
        fields = ['id', 'balance', 'account_type', 'aadhar_number', 'phone_number']
    
    def __str__(self):
        return self.account_type
    
    def validate_aadhar_number(self, value):
        if not value.isdigit():
            raise ValidationError("Aadhar number must contain only digits.")
        if len(value) != 12:
            raise ValidationError("Aadhar number must be exactly 12 digits long.")
        if Savings.objects.filter(aadhar_number=value).exists():
            raise ValidationError("This Aadhar number is already associated with another account.")
        return value
    
    def validate_phone_number(self, value):
        if not value.isdigit():
            raise ValidationError("Phone number must contain only digits.")
        if len(value) != 10:
            raise ValidationError("Phone number must be exactly 10 digits long.")
        return value

    def create(self, validated_data):
        account_type = validated_data.pop('account_type')
        user = self.context['request'].user
        if account_type == 'SAVINGS':
            return Savings.objects.create(user=user, **validated_data)
        elif account_type == 'CURRENT':
            return Savings.objects.create(user=user, **validated_data)



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
        fields = ['email', 'phone_number', 'message']
        extra_kwargs = {
            'email': {'required': True},
            'phone_number': {'required': True},
            'message': {'required': True},
        }


    def validate_message(self, value):
        if not value.strip():  # Check if the message is empty or contains only whitespace
            raise serializers.ValidationError("Message cannot be empty")
        return value

    

class BudgetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Budget
        fields = ['id','category_name', 'allotted_budget', 'start_date', 'end_date']

    def validate(self, data):
        allotted_budget = data.get('allotted_budget')

        if allotted_budget <= 0:
            raise serializers.ValidationError("Allotted budget must be greater than 0.")

        return data


class ExpenseSerializer(serializers.ModelSerializer):
    category = serializers.CharField(max_length=100, write_only=True)

    class Meta:
        model = Expense
        fields = ['id', 'category', 'amount', 'description', 'date']
        read_only_fields = ['user']

    def validate_amount(self, value):
        """
        Validate that the amount field is provided and positive.
        """
        if not value or value <= 0:
            raise serializers.ValidationError("Amount must be a positive number.")
        return value

    def validate_description(self, value):
        """
        Validate that the description field is provided.
        """
        if not value:
            raise serializers.ValidationError("Description field is required.")
        return value

    def create(self, validated_data):
        """
        Create a new expense object.
        """
        user = self.context['request'].user
        category_name = validated_data.pop('category')
        
        # Find the budget with the given category name for the current user
        try:
            budget = user.budget_set.get(category_name=category_name)
        except Budget.DoesNotExist:
            raise serializers.ValidationError(f"No budget found for category '{category_name}'.")

        # Add the budget instance to the validated data
        validated_data['user'] = user
        validated_data['budget'] = budget
        
        return super().create(validated_data)






class SavingsGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = SavingsGoal
        fields = ['id', 'goal_name', 'target_amount', 'current_amount', 'completed']