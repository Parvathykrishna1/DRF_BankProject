from pyexpat.errors import messages
from django.http import Http404
from django.shortcuts import get_object_or_404, render
from rest_framework import generics, status
from rest_framework.permissions import IsAdminUser, IsAuthenticated, AllowAny
from django.contrib.auth import authenticate, logout
from rest_framework.response import Response
from customerportal.serializers import (
    CustomerMessagesSerializer,
    FixedDepositSerializer,
    FundTransferSerializer,
    LoanApplicationSerializer,
    RecurrentDepositSerializer,
    ReviewRatingDbSerializer,
)
from customerportal.models import *
from staffportal.models import *
from .serializers import *
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.core.cache import cache  # For caching login attempts
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.views import APIView


class RegisterNewStaffView(generics.CreateAPIView):
    """
    API view for registering new staff.

    Allows registration of new staff members with the provided details.
    """

    permission_classes = [AllowAny]
    queryset = CustomUser.objects.all()
    serializer_class = RegisterNewAdminSerializer

    def post(self, request):
        """
        Handle POST request for staff registration.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with success or error message.
        """
        serializer = RegisterNewAdminSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(
                {"message": "Staff registration successful", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StaffLoginView(generics.CreateAPIView):
    """
    API view for staff login.

    Allows staff members to log in and generates JWT tokens upon successful authentication.
    """

    permission_classes = [AllowAny]  # Allow any user to attempt login
    queryset = CustomUser.objects.all()
    serializer_class = StaffLoginSerializer
    MAX_LOGIN_ATTEMPTS = 3
    BLOCK_DURATION_SECONDS = 300  # Block user for 5 minutes (300 seconds)

    def post(self, request, *args, **kwargs):
        """
        Handle POST request for staff login.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with JWT tokens or error message.
        """
        serializer = StaffLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")
            user = authenticate(email=email, password=password)

            if user and user.staff:
                # Check if user is blocked
                if cache.get(email):
                    return Response(
                        {
                            "message": "Account is temporarily blocked. Please try again later."
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )

                # Attempt login
                if user.check_password(password):
                    # Clear login attempts on successful login
                    cache.delete(email)

                    # Generate JWT access token
                    access_token = AccessToken.for_user(user)
                    # Generate JWT refresh token
                    refresh_token = RefreshToken.for_user(user)

                    return Response(
                        {
                            "access_token": str(access_token),
                            "refresh_token": str(refresh_token),
                            "message": "Login successful.",
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
                                "message": "Too many failed login attempts. Account blocked."
                            },
                            status=status.HTTP_403_FORBIDDEN,
                        )
                    else:
                        return Response(
                            {"message": "Invalid email or password."},
                            status=status.HTTP_401_UNAUTHORIZED,
                        )
            else:
                return Response(
                    {"message": "Invalid email or password."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StaffLogoutView(generics.GenericAPIView):
    """
    API view for staff logout.

    Allows staff members to log out.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handle POST request for staff logout.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with logout success message.
        """
        logout(request)
        return Response({"message": "Logout Successful"}, status=status.HTTP_200_OK)


class BankAccountListCreateAPIView(APIView):
    """
    API view for listing and creating bank accounts.

    Allows listing all bank accounts and creating new bank accounts.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request, format=None):
        """
        Handle GET request for listing bank accounts.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with list of bank accounts.
        """
        accounts = BankAccount.objects.all()
        serializer = BankAccountSerializer(accounts, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        """
        Handle POST request for creating bank accounts.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with success or error message.
        """
        serializer = BankAccountSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Account created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BankAccountRetrieveUpdateDestroyAPIView(APIView):
    """
    API view for retrieving, updating, and deleting bank accounts.

    Allows retrieving, updating, and deleting bank accounts by their ID.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def get_object(self, pk):
        """
        Retrieve bank account object by ID.

        Args:
            pk: Bank account ID.

        Returns:
            BankAccount: Bank account object.

        Raises:
            Http404: If bank account with the given ID does not exist.
        """
        try:
            return BankAccount.objects.get(pk=pk)
        except BankAccount.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        """
        Handle GET request for retrieving bank account details.

        Args:
            request: HTTP request object.
            pk: Bank account ID.

        Returns:
            Response: HTTP response with bank account details or error message.
        """
        account = self.get_object(pk)
        serializer = BankAccountSerializer(account)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        """
        Handle PUT request for updating bank account details.

        Args:
            request: HTTP request object.
            pk: Bank account ID.

        Returns:
            Response: HTTP response with success or error message.
        """
        account = self.get_object(pk)
        serializer = BankAccountSerializer(account, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Account updated successfully."}, status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        """
        Handle DELETE request for deleting bank account.

        Args:
            request: HTTP request object.
            pk: Bank account ID.

        Returns:
            Response: HTTP response with success or error message.
        """
        account = self.get_object(pk)
        account.delete()
        return Response(
            {"message": "Account deleted successfully."},
            status=status.HTTP_204_NO_CONTENT,
        )


class AllUsersTransactionHistoryAPIView(APIView):
    """
    API view for retrieving transaction history of all accounts associated with a user.

    Allows retrieving transaction history for all accounts associated with a user.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        """
        Handle POST request for retrieving transaction history.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with transaction history or error message.
        """
        account_number = request.data.get("account_number")

        if not account_number:
            return Response(
                {"error": "Account number is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Fetch all accounts with the provided account number
        savings_accounts = Savings.objects.filter(account_number=account_number)
        current_accounts = Savings.objects.filter(account_number=account_number)

        if not (savings_accounts.exists() or current_accounts.exists()):
            return Response(
                {"error": "No accounts found with the provided account number"},
                status=status.HTTP_404_NOT_FOUND,
            )

        response_data = []

        # Retrieve transaction history for each account
        for account in savings_accounts:
            savings_transactions = SavingsTransaction.objects.filter(account=account)
            if savings_transactions.exists():
                savings_data = [
                    {
                        "transaction_type": transaction.transaction_type,
                        "amount": transaction.amount,
                        "date": transaction.date,
                    }
                    for transaction in savings_transactions
                ]
                response_data.append(
                    {
                        "account_number": account.account_number,
                        "account_type": "SAVINGS",
                        "transactions": savings_data,
                    }
                )

        for account in current_accounts:
            current_transactions = CurrentTransaction.objects.filter(account=account)
            if current_transactions.exists():
                current_data = [
                    {
                        "transaction_type": transaction.transaction_type,
                        "amount": transaction.amount,
                        "date": transaction.date,
                    }
                    for transaction in current_transactions
                ]
                response_data.append(
                    {
                        "account_number": account.account_number,
                        "account_type": "CURRENT",
                        "transactions": current_data,
                    }
                )

        if not response_data:
            return Response(
                {"error": "No transactions found for the provided account number"},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(response_data)


class FDAndRDInterestRateAPIView(APIView):
    """
    API view for retrieving and updating fixed deposit and recurring deposit interest rates.

    Allows retrieving and updating fixed deposit and recurring deposit interest rates.
    """

    serializer_class = InterestRateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        """
        Handle GET request for retrieving fixed deposit and recurring deposit interest rates.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with interest rates or error message.
        """
        try:
            interest_rate = FDAndRDInterestRate.objects.get(
                id=1
            )  # Assuming only one interest rate will be stored with ID 1
            serializer = InterestRateSerializer(interest_rate)
            return Response(serializer.data)
        except FDAndRDInterestRate.DoesNotExist:
            return Response(
                {"error": "No interest rate found"}, status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request):
        """
        Handle PUT request for updating fixed deposit and recurring deposit interest rates.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with updated interest rates or error message.
        """
        try:
            interest_rate = FDAndRDInterestRate.objects.get(id=1)
            serializer = InterestRateSerializer(interest_rate, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except FDAndRDInterestRate.DoesNotExist:
            serializer = InterestRateSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(
                    id=1
                )  # Set ID to 1 to ensure only one interest rate exists
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserFixedDepositsAPIView(generics.ListAPIView):
    """
    API view for retrieving fixed deposits of a user.

    Allows retrieving fixed deposits of a user by their user ID.
    """

    serializer_class = FixedDepositSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get_queryset(self):
        """
        Get queryset of fixed deposits for a user.

        Returns:
            QuerySet: Fixed deposit queryset.
        """
        user_id = self.kwargs["user_id"]
        user_fixed_deposits = FixedDeposit.objects.filter(user_id=user_id)
        return user_fixed_deposits


class UserRecurrentDepositsAPIView(generics.ListAPIView):
    """
    API view for retrieving recurring deposits of a user.

    Allows retrieving recurring deposits of a user by their user ID.
    """

    serializer_class = RecurrentDepositSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get_queryset(self):
        """
        Get queryset of recurring deposits for a user.

        Returns:
            QuerySet: Recurrent deposit queryset.
        """
        user_id = self.kwargs["user_id"]
        user_recurrent_deposits = RecurrentDeposit.objects.filter(user_id=user_id)
        return user_recurrent_deposits


class FundTransferListAPIView(generics.ListAPIView):
    """
    API view for listing fund transfers.

    Allows listing all fund transfers.
    """

    queryset = FundTransfer.objects.all()
    serializer_class = FundTransferSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get_queryset(self):
        """
        Get queryset of fund transfers.

        Returns:
            QuerySet: Fund transfer queryset.
        """
        return super().get_queryset()

    def list(self, request, *args, **kwargs):
        """
        Handle GET request for listing fund transfers.

        Args:
            request: HTTP request object.
            *args: Additional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: HTTP response with list of fund transfers.
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class LoanInterestRateCreateAPIView(generics.CreateAPIView):
    """
    API view for creating loan interest rates.

    Allows creating new loan interest rates.
    """

    queryset = LoanInterestRate.objects.all()
    serializer_class = InterestRateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def create(self, request, *args, **kwargs):
        """
        Handle POST request for creating loan interest rates.

        Args:
            request: HTTP request object.
            *args: Additional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: HTTP response with success or error message.
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            loan_type = serializer.validated_data.get("loan_type")
            if LoanInterestRate.objects.filter(loan_type=loan_type).exists():
                return Response(
                    {"error": "An interest rate for this loan type already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            self.perform_create(serializer)
            return Response(
                {"message": "Interest rate created successfully."},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoanInterestRateUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    """
    API view for retrieving, updating, and deleting loan interest rates.

    Allows retrieving, updating, and deleting loan interest rates by their ID.
    """

    queryset = LoanInterestRate.objects.all()
    serializer_class = InterestRateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]


class LoanInterestListAPIView(generics.ListAPIView):
    """
    API view for listing loan interest rates.

    Allows listing all loan interest rates.
    """

    queryset = LoanInterestRate.objects.all()
    serializer_class = InterestRateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]


class LoanApprovalAPIView(generics.CreateAPIView):
    """
    API view for approving or rejecting loan applications.

    Allows approving or rejecting loan applications and sending notification emails to users.
    """

    queryset = LoanApproval.objects.all()
    serializer_class = LoanApprovalSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def create(self, request, *args, **kwargs):
        """
        Handle POST request for approving or rejecting loan applications.

        Args:
            request: HTTP request object.
            *args: Additional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: HTTP response with success or error message.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Update loan application status
        loan_application = serializer.validated_data["loan_application"]
        new_status = serializer.validated_data["new_status"]
        loan_application.status = new_status
        loan_application.save()

        # Create loan approval instance
        loan_approval = serializer.save()

        send_mail(
            "Loan Approval Notification",
            f"Your loan application for {loan_application.loan_type} has been {new_status.lower()}.",
            "tkmce.alumniportal@gmail.com",
            [loan_application.user.email],
            fail_silently=True,
        )

        return Response(
            {"message": "Loan status updated and notification sent"},
            status=status.HTTP_201_CREATED,
        )


class UserLoanApplicationListView(generics.ListAPIView):
    """
    API view for listing loan applications.

    Allows listing all loan applications.
    """

    serializer_class = LoanApplicationSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get_queryset(self):
        """
        Get queryset of loan applications.

        Returns:
            QuerySet: Loan application queryset.
        """
        return LoanApplication.objects.all()


class BlockUserAPIView(APIView):
    """
    API view for blocking a user.

    Allows blocking a user by their ID.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request, userid):
        """
        Handle POST request for blocking a user.

        Args:
            request: HTTP request object.
            userid: User ID.

        Returns:
            Response: HTTP response with success or error message.
        """
        user = get_object_or_404(CustomUser, id=userid)
        user.is_blocked = True
        user.save()
        return Response(
            {"message": "User has been successfully blocked."},
            status=status.HTTP_200_OK,
        )


class UnblockUserAPIView(APIView):
    """
    API view for unblocking a user.

    Allows unblocking a user by their ID.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request, userid):
        """
        Handle POST request for unblocking a user.

        Args:
            request: HTTP request object.
            userid: User ID.

        Returns:
            Response: HTTP response with success or error message.
        """
        user = get_object_or_404(CustomUser, id=userid)
        if user.is_blocked:
            user.is_blocked = False
            user.failed_login_attempts = 0
            user.save()
            return Response(
                {"message": "User has been successfully unblocked."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"error": "User is not blocked."}, status=status.HTTP_400_BAD_REQUEST
            )


class CustomerReviewDisplayAPIView(APIView):
    """
    API view for displaying customer reviews.

    Allows displaying all customer reviews.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        """
        Handle GET request for displaying customer reviews.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with customer reviews.
        """
        reviews = ReviewRatingDb.objects.all()
        serializer = ReviewRatingDbSerializer(reviews, many=True)
        return Response(serializer.data)


class DeleteReviewAPIView(APIView):
    """
    API view for deleting a customer review.

    Allows deleting a customer review by its ID.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def delete(self, request, review_id):
        """
        Handle DELETE request for deleting a customer review.

        Args:
            request: HTTP request object.
            review_id: Review ID.

        Returns:
            Response: HTTP response with success or error message.
        """
        try:
            review = ReviewRatingDb.objects.get(id=review_id)
            review.delete()
            return Response(
                {"message": "Review is deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except ReviewRatingDb.DoesNotExist:
            return Response(
                {"error": "Review not found"}, status=status.HTTP_404_NOT_FOUND
            )


class NewsListAPIView(APIView):
    """
    API view for listing news items.

    Allows listing all news items and creating new news items.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        """
        Handle GET request for listing news items.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with list of news items.
        """
        news = BankNews.objects.all()
        serializer = BankNewsSerializer(news, many=True)
        return Response(serializer.data)

    def post(self, request):
        """
        Handle POST request for creating news items.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with success or error message.
        """
        serializer = BankNewsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NewsDetailAPIView(APIView):
    """
    API view for retrieving, updating, and deleting news items.

    Allows retrieving, updating, and deleting news items by their ID.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def get_object(self, news_id):
        """
        Retrieve news item object by ID.

        Args:
            news_id: News item ID.

        Returns:
            BankNews: News item object.
        """
        try:
            return BankNews.objects.get(id=news_id)
        except BankNews.DoesNotExist:
            return None

    def get(self, request, news_id):
        """
        Handle GET request for retrieving news item details.

        Args:
            request: HTTP request object.
            news_id: News item ID.

        Returns:
            Response: HTTP response with news item details or error message.
        """
        news = self.get_object(news_id)
        if news:
            serializer = BankNewsSerializer(news)
            return Response(serializer.data)
        return Response({"error": "News not found"}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, news_id):
        """
        Handle PUT request for updating news item details.

        Args:
            request: HTTP request object.
            news_id: News item ID.

        Returns:
            Response: HTTP response with success or error message.
        """
        news = self.get_object(news_id)
        if news:
            serializer = BankNewsSerializer(news, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "News not found"}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, news_id):
        """
        Handle DELETE request for deleting a news item.

        Args:
            request: HTTP request object.
            news_id: News item ID.

        Returns:
            Response: HTTP response with success or error message.
        """
        news = self.get_object(news_id)
        if news:
            news.delete()
            return Response(
                {"message": "News item is deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        return Response({"error": "News not found"}, status=status.HTTP_404_NOT_FOUND)


class CustomerMessagesListAPIView(APIView):
    """
    API view for listing customer messages.

    Allows listing all customer messages.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        """
        Handle GET request for listing customer messages.

        Args:
            request: HTTP request object.

        Returns:
            Response: HTTP response with list of customer messages.
        """
        messages = CustomerMessages.objects.all()
        serializer = CustomerMessagesSerializer(messages, many=True)
        return Response(serializer.data)


class CustomerMessageDetailAPIView(APIView):
    """
    API view for retrieving and deleting customer messages.

    Allows retrieving and deleting customer messages by their ID.
    """

    permission_classes = [IsAuthenticated, IsAdminUser]

    def get_object(self, message_id):
        """
        Retrieve customer message object by ID.

        Args:
            message_id: Message ID.

        Returns:
            CustomerMessages: Customer message object.
        """
        try:
            return CustomerMessages.objects.get(id=message_id)
        except CustomerMessages.DoesNotExist:
            return None

    def get(self, request, message_id):
        """
        Handle GET request for retrieving customer message details.

        Args:
            request: HTTP request object.
            message_id: Message ID.

        Returns:
            Response: HTTP response with customer message details or error message.
        """
        message = self.get_object(message_id)
        if message:
            serializer = CustomerMessagesSerializer(message)
            return Response(serializer.data)
        return Response(
            {"error": "Message not found"}, status=status.HTTP_404_NOT_FOUND
        )

    def delete(self, request, message_id):
        """
        Handle DELETE request for deleting a customer message.

        Args:
            request: HTTP request object.
            message_id: Message ID.

        Returns:
            Response: HTTP response with success or error message.
        """
        message = self.get_object(message_id)
        if message:
            message.delete()
            return Response(
                {"message": "Message is deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        return Response(
            {"error": "Message not found"}, status=status.HTTP_404_NOT_FOUND
        )
