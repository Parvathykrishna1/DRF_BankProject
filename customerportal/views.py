from datetime import timedelta
from decimal import Decimal
from pyexpat.errors import messages
from django.shortcuts import get_object_or_404, render
from django.views import View
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate, logout
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import PermissionDenied
from staffportal.models import BankAccount, FDAndRDInterestRate, LoanInterestRate
from staffportal.serializers import BankAccountSerializer
from .serializers import *
from django.core.mail import send_mail
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth import update_session_auth_hash


from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate, logout
from django.core.cache import cache
from rest_framework import generics, status
from rest_framework.response import Response
from .serializers import CustomerRegistrationSerializer, CustomerLoginSerializer


class CustomerRegistrationView(generics.CreateAPIView):
    """
    Register a new customer.

    This endpoint allows new customers to join AX Bank and start their financial journey!

    Upon successful registration, a confirmation email will be sent to the provided email address.
    """

    permission_classes = [AllowAny]
    queryset = User.objects.all()
    serializer_class = CustomerRegistrationSerializer

    def post(self, request):
        """
        Handle new customer registration.

        After successful registration, a confirmation email will be sent to the provided email address.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating registration status.
        """
        serializer = CustomerRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Send registration confirmation email
            send_registration_email(user.email)
            return Response(
                {
                    "message": "Welcome aboard! Your registration was successful.",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def send_registration_email(email):
    """
    Send registration confirmation email.

    Welcome our new customer to AX Bank!

    Args:
        email: Email address of the new user.
    """
    subject = "Welcome to AX Bank!"
    message = (
        "Congratulations on joining AX Bank! Your registration was successful."
        " We're thrilled to have you on board."
    )
    sender_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, sender_email, recipient_list)


class CustomerLoginView(APIView):
    """
    Log in to AX Bank.

    This endpoint allows existing customers to log in to their AX Bank accounts.

    After successful login, customers will receive access to their accounts with AX Bank.

    Too many failed login attempts will temporarily block access for security purposes.
    """

    permission_classes = [AllowAny]
    serializer_class = CustomerLoginSerializer
    MAX_LOGIN_ATTEMPTS = 3
    BLOCK_DURATION_SECONDS = 5

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")
            user = authenticate(email=email, password=password)

            if user:
                # Clear any existing login attempts
                cache.delete(email)

                # Attempt login
                if user.check_password(password):
                    # Generate JWT access token and refresh token
                    refresh = RefreshToken.for_user(user)
                    return Response(
                        {
                            "access_token": str(refresh.access_token),
                            "refresh_token": str(refresh),
                            "message": "Welcome back! You're now logged in.",
                        },
                        status=status.HTTP_200_OK,
                    )
            else:
                # Increment login attempt count
                attempts = cache.get(email, 0)
                attempts += 1
                cache.set(email, attempts, self.BLOCK_DURATION_SECONDS)

                # Check if login attempts exceed threshold
                if attempts >= self.MAX_LOGIN_ATTEMPTS:
                    return Response(
                        {
                            "message": "Too many failed login attempts. Account blocked 300seconds."
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )

            # Invalid email or password
            return Response(
                {"message": "Invalid email or password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomerLogoutView(generics.GenericAPIView):
    """
    Log out from AX Bank.

    This endpoint allows customers to securely log out from their AX Bank accounts.

    After successful logout, customers will be signed out from their accounts.
    """

    def post(self, request, *args, **kwargs):
        """
        Handle customer logout.

        After successful logout, customers will be signed out from their AX Bank accounts.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating logout status.
        """
        logout(request)
        return Response(
            {"message": "You're now securely logged out. Have a great day!"},
            status=status.HTTP_200_OK,
        )


class PasswordResetView(APIView):
    """
    View for resetting user password.

    Allows authenticated users to reset their password.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handles POST request for resetting user password.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating password reset status.
        """
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            new_password = serializer.validated_data.get("new_password")
            # Perform password validation here if needed
            user.set_password(new_password)
            user.save()
            update_session_auth_hash(request, user)
            return Response(
                {"message": "Password changed successfully."}, status=status.HTTP_200_OK
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateProfileAPIView(APIView):
    """
    View for updating user profile.

    Allows authenticated users to update their profile information.
    """

    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def get(self, request):
        """
        Handles GET request for retrieving user profile.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response with user profile data.
        """
        user = self.get_object()
        serializer = CustomerRegistrationSerializer(user)
        return Response(serializer.data)

    def put(self, request):
        """
        Handles PUT request for updating user profile.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating profile update status.
        """
        user = self.get_object()
        serializer = CustomerRegistrationSerializer(
            user, data=request.data, partial=True
        )  # Set partial=True
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Profile updated successfully"}, status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BankAccountListView(APIView):
    """
    View to list bank accounts.

    Allows authenticated users to list all bank accounts.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Handles GET request to list bank accounts.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response with serialized bank account data.
        """
        bank_accounts = BankAccount.objects.all()
        serializer = BankAccountSerializer(bank_accounts, many=True)
        return Response(serializer.data)


class CreateAccountAPIView(APIView):
    """
    View to create a bank account.

    Allows authenticated users to create a new bank account.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handles POST request to create a bank account.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating account creation status.
        """
        serializer = AccountSerializer(data=request.data)
        if serializer.is_valid():
            serializer.validated_data["user"] = request.user
            account = serializer.save()
            account_number = account.account_number
            message = f"Account created successfully. Your account number is: {account_number}"
            return Response({"message": message}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserAccountAPIView(APIView):
    """
    View to retrieve user's account details.

    Allows authenticated users to view details of their accounts.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Handles GET request to retrieve user's account details.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response with serialized user account data.
        """
        user_accounts = Savings.objects.filter(user=request.user)
        if not user_accounts.exists():
            raise PermissionDenied("You don't have any accounts.")

        username = request.user.username
        serializer = AccountSerializer(user_accounts, many=True)
        accounts_data = serializer.data

        for account_data, account in zip(accounts_data, user_accounts):
            account_data["user"] = username
            account_data["account_number"] = account.account_number

        return Response(accounts_data)


class DeleteAccountAPIView(APIView):
    """
    View to delete a bank account.

    Allows authenticated users to delete their bank accounts.
    """

    permission_classes = [IsAuthenticated]

    def delete(self, request, format=None):
        """
        Handles DELETE request to delete a bank account.

        Args:
            request: HTTP request object.
            format: Format of the request (optional).

        Returns:
            HTTP response indicating account deletion status.
        """
        account_number = request.data.get("account_number")
        if not account_number:
            return Response(
                {"error": "Account number is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        account = get_object_or_404(Savings, account_number=account_number)
        if account.balance == 0:
            account.delete()
            return Response(
                {"message": "Account deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        else:
            return Response(
                {"error": "Cannot delete account with non-zero balance"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class DepositAPIView(generics.GenericAPIView):
    """
    View for depositing funds into a user's savings account.

    Allows authenticated users to deposit funds into their savings account.
    """

    serializer_class = DepositSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handles POST request for depositing funds.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating deposit status.
        """
        account_number = request.data.get("account_number")
        amount = request.data.get("amount")
        description = request.data.get("description", "")

        if not account_number or not amount:
            return Response(
                {"error": "Both account_number and amount are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Retrieve the savings account associated with the current user
        savings_account = get_object_or_404(
            Savings, account_number=account_number, user=request.user
        )

        serializer = self.get_serializer(
            data={"amount": amount, "description": description}
        )

        if serializer.is_valid():
            amount = serializer.validated_data.get("amount")
            description = serializer.validated_data.get("description", "")
            try:
                # Make the deposit to the savings account
                savings_account.deposit(amount, description)
                new_balance = savings_account.balance
                return Response(
                    {"message": "Deposit successful", "new_balance": new_balance},
                    status=status.HTTP_200_OK,
                )
            except ValueError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class WithdrawalAPIView(generics.GenericAPIView):
    """
    View for withdrawing funds from a user's savings account.

    Allows authenticated users to withdraw funds from their savings account.
    """

    serializer_class = WithdrawalSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handles POST request for withdrawing funds.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating withdrawal status.
        """
        account_number = request.data.get("account_number")
        amount = request.data.get("amount")
        description = request.data.get("description", "")

        if not account_number or not amount:
            return Response(
                {"error": "Both account_number and amount are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify that the account being accessed belongs to the authenticated user
        savings_account = get_object_or_404(
            Savings, account_number=account_number, user=request.user
        )

        serializer = self.get_serializer(data={"amount": amount})

        if serializer.is_valid():
            amount = serializer.validated_data.get("amount")
            if amount > savings_account.balance:
                return Response(
                    {"error": "Insufficient funds"}, status=status.HTTP_400_BAD_REQUEST
                )

            try:
                savings_account.withdraw(amount, description)
                new_balance = savings_account.balance
                return Response(
                    {"message": "Withdrawal successful", "new_balance": new_balance},
                    status=status.HTTP_200_OK,
                )
            except ValueError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class TransactionHistoryAPIView(APIView):
    """
    View for retrieving transaction history of a user's savings account.

    Allows authenticated users to view their transaction history.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handles POST request for retrieving transaction history.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response with transaction history data.
        """
        account_number = request.data.get("account_number")

        if not account_number:
            return Response(
                {"error": "Account number is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Ensure that the requested account belongs to the current user
        account = get_object_or_404(
            Savings, account_number=account_number, user=request.user
        )
        savings_transactions = SavingsTransaction.objects.filter(account=account)
        current_transactions = CurrentTransaction.objects.filter(account=account)

        response_data = {}

        if savings_transactions.exists():
            savings_data = [
                {
                    "transaction_type": transaction.transaction_type,
                    "amount": transaction.amount,
                    "date": transaction.date,
                }
                for transaction in savings_transactions
            ]
            response_data["savings_transactions"] = savings_data

        if current_transactions.exists():
            current_data = [
                {
                    "transaction_type": transaction.transaction_type,
                    "amount": transaction.amount,
                    "date": transaction.date,
                }
                for transaction in current_transactions
            ]
            response_data["current_transactions"] = current_data

        if not response_data:
            return Response(
                {"error": "No transactions found for the provided account number"},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(response_data)


class FixedDepositCreateAPIView(generics.CreateAPIView):
    """
    API view for creating a fixed deposit.

    Allows authenticated users to create fixed deposits.
    """

    queryset = FixedDeposit.objects.all()
    serializer_class = FixedDepositSerializer
    permission_classes = [IsAuthenticated]

    def calculate_total_amount(self, amount, interest_rate, duration_months):
        """
        Calculate the total amount after the fixed deposit duration.

        Args:
            amount (Decimal): The initial deposit amount.
            interest_rate (InterestRate): The interest rate for the fixed deposit.
            duration_months (int): The duration of the fixed deposit in months.

        Returns:
            Decimal: The total amount after the fixed deposit duration.
        """
        duration_days = duration_months * 30
        total_amount = amount * (1 + Decimal(interest_rate.rate) / 100) ** (
            duration_days / Decimal(365)
        )
        return total_amount

    def create(self, request, *args, **kwargs):
        """
        Handle POST request for creating a fixed deposit.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating the result of the fixed deposit creation.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        amount = serializer.validated_data["amount"]
        duration_months = serializer.validated_data["duration_months"]
        start_date = timezone.now().date()
        end_date = start_date + timedelta(days=duration_months * 30)

        interest_rate = FDAndRDInterestRate.objects.first()

        total_amount = self.calculate_total_amount(
            amount, interest_rate, duration_months
        )

        serializer.save(user=request.user, end_date=end_date, total_amount=total_amount)

        response_data = serializer.data
        response_data["end_date"] = end_date
        response_data["total_amount"] = total_amount

        return Response(response_data, status=status.HTTP_201_CREATED)


class FixedDepositListAPIView(generics.ListAPIView):
    """
    API view for retrieving a list of fixed deposits.

    Allows authenticated users to retrieve a list of their fixed deposits.
    """

    queryset = FixedDeposit.objects.all()
    serializer_class = FixedDepositSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get the queryset filtered by the current user.

        Returns:
            QuerySet: The filtered queryset of fixed deposits.
        """
        user = self.request.user
        return FixedDeposit.objects.filter(user=user)

    def list(self, request, *args, **kwargs):
        """
        Handle GET request for retrieving a list of fixed deposits.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response containing the list of fixed deposits.
        """
        queryset = self.get_queryset()

        if not queryset.exists():
            return Response(
                {"message": "No fixed deposits found for the current user."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class RecurrentDepositCreateAPIView(generics.CreateAPIView):
    """
    API view for creating a recurrent deposit.

    Allows authenticated users to create recurrent deposits.
    """

    queryset = RecurrentDeposit.objects.all()
    serializer_class = RecurrentDepositSerializer
    permission_classes = [IsAuthenticated]

    def calculate_total_amount(self, amount, interest_rate, duration_days):
        """
        Calculate the total amount after the recurrent deposit duration.

        Args:
            amount (Decimal): The initial deposit amount.
            interest_rate (InterestRate): The interest rate for the recurrent deposit.
            duration_days (int): The duration of the recurrent deposit in days.

        Returns:
            Decimal: The total amount after the recurrent deposit duration.
        """
        total_amount = amount * (1 + Decimal(interest_rate.rate) / 100) ** (
            duration_days / Decimal(365)
        )
        return total_amount

    def create(self, request, *args, **kwargs):
        """
        Handle POST request for creating a recurrent deposit.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating the result of the recurrent deposit creation.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        amount = serializer.validated_data["amount"]
        frequency = serializer.validated_data["frequency"]
        start_date = timezone.now().date()
        if frequency == "MONTHLY":
            end_date = start_date + timedelta(days=30)
        elif frequency == "QUARTERLY":
            end_date = start_date + timedelta(days=90)
        elif frequency == "HALF_YEARLY":
            end_date = start_date + timedelta(days=182)
        elif frequency == "YEARLY":
            end_date = start_date + timedelta(days=365)
        else:
            return Response(
                {"error": "Invalid frequency"}, status=status.HTTP_400_BAD_REQUEST
            )

        duration_days = (end_date - start_date).days

        interest_rate = FDAndRDInterestRate.objects.first()

        if not interest_rate:
            return Response(
                {"error": "No interest rate found"}, status=status.HTTP_400_BAD_REQUEST
            )

        total_amount = self.calculate_total_amount(amount, interest_rate, duration_days)

        serializer.save(user=request.user, end_date=end_date, total_amount=total_amount)

        response_data = serializer.data
        response_data["total_amount_after_duration"] = total_amount
        response_data["end_date"] = end_date

        return Response(response_data, status=status.HTTP_201_CREATED)


class RecurrentDepositListAPIView(generics.ListAPIView):
    """
    API view for retrieving a list of recurrent deposits.

    Allows authenticated users to retrieve a list of their recurrent deposits.
    """

    queryset = FixedDeposit.objects.all()
    serializer_class = RecurrentDepositSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get the queryset filtered by the current user.

        Returns:
            QuerySet: The filtered queryset of recurrent deposits.
        """
        user = self.request.user
        return RecurrentDeposit.objects.filter(user=user)

    def list(self, request, *args, **kwargs):
        """
        Handle GET request for retrieving a list of recurrent deposits.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response containing the list of recurrent deposits.
        """
        queryset = self.get_queryset()

        if not queryset.exists():
            return Response(
                {"message": "No fixed deposits found for the current user."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class FundTransferAPIView(APIView):
    """
    API view for transferring funds between accounts.

    Allows authenticated users to transfer funds between their accounts.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handle POST request for transferring funds.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating the result of the fund transfer.
        """
        serializer = FundTransferSerializer(data=request.data)
        if serializer.is_valid():
            receiver_account_number = serializer.validated_data[
                "receiver_account_number"
            ]
            amount = serializer.validated_data["amount"]

            sender_accounts = request.user.savings_set.all()
            if not sender_accounts.exists():
                return Response(
                    {"error": "Sender account not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            sender_account_number = serializer.validated_data["sender_account_number"]
            try:
                sender_account = sender_accounts.get(
                    account_number=sender_account_number
                )
            except Savings.DoesNotExist:
                return Response(
                    {"error": "Sender account not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            try:
                receiver_account = Savings.objects.get(
                    account_number=receiver_account_number
                )
            except Savings.DoesNotExist:
                return Response(
                    {"error": "Receiver account not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            if sender_account.balance < amount:
                return Response(
                    {"error": "Insufficient balance"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            sender_account.balance -= amount
            receiver_account.balance += amount
            sender_account.save()
            receiver_account.save()

            serializer.save(sender_account_number=sender_account.account_number)

            new_balance = sender_account.balance
            response_data = serializer.data
            response_data["new_sender_balance"] = new_balance

            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        """
        Handle GET request for retrieving fund transfer details.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response containing fund transfer details.
        """
        user_accounts = request.user.savings_set.values_list(
            "account_number", "account_type"
        )

        fund_transfers = FundTransfer.objects.filter(
            sender_account_number__in=[account[0] for account in user_accounts]
        )

        serializer = FundTransferSerializer(fund_transfers, many=True)

        response_data = serializer.data
        for idx, transfer in enumerate(response_data):
            response_data[idx]["sender_account_type"] = dict(user_accounts).get(
                transfer["sender_account_number"], None
            )

        return Response(response_data)


class FundTransferListAPIView(generics.ListAPIView):
    """
    API view for listing fund transfers.

    Allows listing all fund transfers.
    """

    serializer_class = FundTransferSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get queryset of fund transfers for the authenticated user.

        Returns:
            QuerySet: Fund transfer queryset filtered by sender_account_number.
        """
        user = self.request.user
        return FundTransfer.objects.filter(user=user)

    def list(self, request, *args, **kwargs):
        """
        Handle GET request for listing fund transfers.

        Args:
            request: HTTP request object.
            *args: Additional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: HTTP response with list of fund transfers or message if no transfers found.
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        if not queryset:
            return Response(
                {"message": "No fund transfers found for the current user."}
            )
        return Response(serializer.data)


class LoanApplicationCreateAPIView(generics.CreateAPIView):
    """
    API view for creating a loan application.

    Allows authenticated users to apply for loans.
    """

    queryset = LoanApplication.objects.all()
    serializer_class = LoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        """
        Handle POST request for creating a loan application.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating the result of the loan application creation.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.validated_data["user"] = request.user

        loan_type = serializer.validated_data["loan_type"]
        amount = Decimal(serializer.validated_data["amount"])
        duration_years = Decimal(
            serializer.validated_data["duration_months"]
        ) / Decimal("12")

        try:
            interest_rate_obj = LoanInterestRate.objects.get(loan_type=loan_type)
            interest_rate = Decimal(interest_rate_obj.rate) / Decimal("100")
        except LoanInterestRate.DoesNotExist:
            interest_rate = Decimal("0.10")  # Default interest rate of 10%

        monthly_interest_rate = interest_rate / Decimal("12")
        total_payments = duration_years * Decimal("12")
        monthly_payment = (amount * monthly_interest_rate) / (
            Decimal("1") - (Decimal("1") + monthly_interest_rate) ** -total_payments
        )
        total_amount_payable = monthly_payment * total_payments

        self.perform_create(serializer)
        loan_application = serializer.instance

        return Response(
            {
                "loan_details": {
                    "Loan Amount": f"Rs {amount}",
                    "Tenure": f"{duration_years} years",
                    "Interest Rate": f"{interest_rate * 100}%",
                    "Total Amount Payable After Loan Term": f"Rs {total_amount_payable}",
                    "Monthly Payment (EMI)": f"Rs {monthly_payment}",
                    "Applied Date": loan_application.applied_date.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "Status": loan_application.status,
                },
                "message": "Loan application created successfully.",
            },
            status=status.HTTP_201_CREATED,
        )


class LoanApplicationListAPIView(generics.ListAPIView):
    """
    API view for retrieving a list of loan applications.

    Allows authenticated users to retrieve a list of their loan applications.
    """

    serializer_class = LoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get the queryset filtered by the current user.

        Returns:
            QuerySet: The filtered queryset of loan applications.
        """
        user = self.request.user
        return LoanApplication.objects.filter(user=user)


class RatingReviewAPIView(APIView):
    """
    API view for managing ratings and reviews.

    Allows users to retrieve and submit ratings and reviews.
    """

    def get(self, request):
        """
        Handle GET request for retrieving ratings and reviews.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response containing the ratings and reviews.
        """
        customer_id = request.user.id
        ratings_reviews = ReviewRatingDb.objects.filter(user_id=customer_id)
        serializer = ReviewRatingDbSerializer(ratings_reviews, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Handle POST request for submitting ratings and reviews.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating the result of the rating and review submission.
        """
        customer_id = request.user.id
        customer_rating = request.data.get("rating")

        if customer_rating is None:
            return Response(
                {"error": "rating is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        obj = ReviewRatingDb.objects.create(
            user_id=customer_id,
            rating=customer_rating,
        )
        return Response(
            {"message": "Rating saved successfully"},
            status=status.HTTP_201_CREATED,
        )


from rest_framework.response import Response
from rest_framework import status
from .models import CustomerMessages
from .serializers import CustomerMessagesSerializer


class SaveCustomerMessagesAPIView(APIView):
    """
    API view for saving customer messages.

    Allows users to submit messages to the bank.
    """

    def post(self, request):
        """
        Handle POST request for saving customer messages.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating the result of the message submission.
        """
        customer_email = request.user.email
        email_ = request.data.get("email")
        phone_no_ = request.data.get("phone_no")
        message_ = request.data.get("message")

        serializer = CustomerMessagesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(
                {"message": "Your message has been sent successfully"},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )


class BudgetAPIView(APIView):
    """
    API view for managing user budgets.

    Allows users to create, retrieve, update, and delete budgets.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handle POST request for creating a budget.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response indicating the result of the budget creation.
        """
        serializer = BudgetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(
                {"message": "Budget created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        """
        Handle GET request for retrieving budgets.

        Args:
            request: HTTP request object.

        Returns:
            HTTP response containing the budgets.
        """
        budget_controls = Budget.objects.filter(user=request.user)
        serializer = BudgetSerializer(budget_controls, many=True)
        return Response(
            {
                "message": "Budget controls retrieved successfully",
                "data": serializer.data,
            }
        )

    def put(self, request, pk):
        """
        Handle PUT request for updating a budget.

        Args:
            request: HTTP request object.
            pk: Primary key of the budget.

        Returns:
            HTTP response indicating the result of the budget update.
        """
        try:
            budget_control = Budget.objects.get(pk=pk)
        except Budget.DoesNotExist:
            return Response(
                {"error": "Budget control not found"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = BudgetSerializer(budget_control, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Budget updated successfully", "data": serializer.data}
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """
        Handle DELETE request for deleting a budget.

        Args:
            request: HTTP request object.
            pk: Primary key of the budget.

        Returns:
            HTTP response indicating the result of the budget deletion.
        """
        try:
            budget_control = Budget.objects.get(pk=pk)
        except Budget.DoesNotExist:
            return Response(
                {"error": "Budget not found"}, status=status.HTTP_404_NOT_FOUND
            )

        budget_control.delete()
        return Response(
            {"message": "Budget deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )


class ExpenseListCreateAPIView(generics.ListCreateAPIView):
    """
    API view for managing expenses.

    Allows users to list and create expenses.
    """

    serializer_class = ExpenseSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get the queryset filtered by the current user.

        Returns:
            QuerySet: The filtered queryset of expenses.
        """
        return Expense.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """
        Perform creation of an expense.

        Args:
            serializer: Serializer instance for the expense.

        Returns:
            None
        """
        expense = serializer.save(user=self.request.user)
        category = expense.budget.category_name
        amount = expense.amount

        budget = expense.budget
        if amount > budget.allotted_budget:
            subject = "Budget Alert: High Expenses"
            message = (
                f"Dear {self.request.user.username},\n\n"
                f"Your expense for the category '{category}' exceeded the allotted budget.\n\n"
                f"Category: {category}\n"
                f"Expense Amount: ${amount}\n"
                f"Allotted Budget: ${budget.allotted_budget}\n"
                f"Transaction Date: {expense.date}\n\n"
                f"Please review your expenses and adjust accordingly.\n\n"
                f"Best regards,\nAX Bank Team"
            )
            from_email = "axbank@gmail.com"
            to_email = [self.request.user.email]
            send_mail(subject, message, from_email, to_email)

        return Response(
            {"message": "Expense created successfully", "data": serializer.data},
            status=status.HTTP_201_CREATED,
        )


class SavingsGoalListCreateAPIView(generics.ListCreateAPIView):
    """
    API view for listing and creating savings goals.

    Allows authenticated users to list their savings goals and create new ones.
    """

    serializer_class = SavingsGoalSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get the queryset filtered by the current user.

        Returns:
            QuerySet: The filtered queryset of savings goals.
        """
        return SavingsGoal.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """
        Perform creation of a savings goal.

        Args:
            serializer: Serializer instance for the savings goal.

        Returns:
            None
        """
        serializer.save(user=self.request.user)


class SavingsGoalDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    """
    API view for retrieving, updating, and deleting a savings goal.

    Allows authenticated users to view, update, and delete their savings goals.
    """

    serializer_class = SavingsGoalSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get the queryset filtered by the current user.

        Returns:
            QuerySet: The filtered queryset of savings goals.
        """
        return SavingsGoal.objects.filter(user=self.request.user)

    def perform_update(self, serializer):
        """
        Perform update of a savings goal.

        Args:
            serializer: Serializer instance for the savings goal.

        Returns:
            None
        """
        instance = serializer.save()
        if instance.completed:
            # Notify user that the savings goal has been completed
            instance.send_notification()
