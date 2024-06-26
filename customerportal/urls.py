from django.urls import path
from .views import *

urlpatterns = [
    path('register/', CustomerRegistrationView.as_view(), name='customer_register'),
    path('login/', CustomerLoginView.as_view(), name='customer_login'),
    path('logout/', CustomerLogoutView.as_view(), name='customer_logout'),
    path('password/reset/', PasswordResetView.as_view(), name='password_reset'),
    path('profile/', UpdateProfileAPIView.as_view(), name='update_profile'),
    path('bank/accounts/', BankAccountListView.as_view(), name='bank_accounts_list'),
    path('bank/accounts/create/', CreateAccountAPIView.as_view(), name='create_account'),
    path('bank/useraccounts/', UserAccountAPIView.as_view(), name='user_accounts'),
    path('bank/accounts/delete/', DeleteAccountAPIView.as_view(), name='delete_account'),
    path('bank/accounts/deposit/', DepositAPIView.as_view(), name='deposit'), 
    path('bank/accounts/withdrawal/', WithdrawalAPIView.as_view(), name='withdrawal'),
    path('bank/accounts/transaction/history/', TransactionHistoryAPIView.as_view(), name='transaction_history'),
    path('bank/accounts/fixed-deposit/create/', FixedDepositCreateAPIView.as_view(), name='fixed_deposit_create'),
    path('bank/accounts/fixed-deposit/list/', FixedDepositListAPIView.as_view(), name='fixed_deposit_list'),
    path('bank/accounts/recurrent-deposit/create/', RecurrentDepositCreateAPIView.as_view(), name='recurrent_deposit_create'),
    path('bank/accounts/recurrent-deposit/list/', RecurrentDepositListAPIView.as_view(), name='recurrent_deposit_list'),
    path('bank/accounts/fund-transfer/', FundTransferAPIView.as_view(), name='fund_transfer'),
    path('fund-transfers/list/', FundTransferListAPIView.as_view(), name='fund_transfer_list'),
    path('bank/accounts/loan-application/create/', LoanApplicationCreateAPIView.as_view(), name='loan_application_create'),
    path('loan-applications/', LoanApplicationListAPIView.as_view(), name='loan-application-list'),
    path('ratings-reviews/', RatingReviewAPIView.as_view(), name='ratings_reviews'),
    path('messages/save/', SaveCustomerMessagesAPIView.as_view(), name='save_customer_messages'),
    path('budget-control/', BudgetAPIView.as_view(), name='budget-control'),
    path('budget-control/<int:pk>/', BudgetAPIView.as_view(), name='budget-control-detail'), 
    path('expenses/', ExpenseListCreateAPIView.as_view(), name='expense-list-create'), 
    path('savings-goals/', SavingsGoalListCreateAPIView.as_view(), name='savings-goal-list-create'),
    path('savings-goals/<int:pk>/', SavingsGoalDetailAPIView.as_view(), name='savings-goal-detail'),
]