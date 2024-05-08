from django.urls import path
from .views import *

urlpatterns = [
    path('register/', RegisterNewStaffView.as_view(), name='staff_register'),
    path('login/', StaffLoginView.as_view(), name='staff_login'),
    path('logout/', StaffLogoutView.as_view(), name='staff_logout'),
    path('accounts/', BankAccountListCreateAPIView.as_view(), name='account_list_create'),
    path('accounts/<int:pk>/', BankAccountRetrieveUpdateDestroyAPIView.as_view(), name='account_detail'),
    path('transaction-history/', AllUsersTransactionHistoryAPIView.as_view(), name='admin_transaction_history'),
    path('fd-rd-interest-rate/', FDAndRDInterestRateAPIView.as_view(), name='admin_interest_rate'),
    path('fixed-deposits/user/<int:user_id>/', UserFixedDepositsAPIView.as_view(), name='admin_user_fixed_deposits'),
    path('recurrent-deposits/user/<int:user_id>/', UserRecurrentDepositsAPIView.as_view(), name='admin_user_recurrent_deposits'),
    path('loan-interest-rate/create/', LoanInterestRateCreateAPIView.as_view(), name='loan_interest_rate_create'),
    path('loan-interest-rate/<int:pk>/', LoanInterestRateUpdateDestroyAPIView.as_view(), name='loan_interest_rate_detail'),
    path('loan-interest-rate/list/', LoanInterestListAPIView.as_view(), name='loan_interest_rate_list'),
    path('loan-approval/', LoanApprovalAPIView.as_view(), name='admin_loan_approval'),
    path('loan-applications/', UserLoanApplicationListView.as_view(), name='admin_loan_applications'),
    path('block-user/<int:userid>/', BlockUserAPIView.as_view(), name='admin_block_user'),
    path('unblock-user/<int:userid>/', UnblockUserAPIView.as_view(), name='admin_unblock_user'),
    path('customer-reviews/', CustomerReviewDisplayAPIView.as_view(), name='admin_customer_reviews'),
    path('delete-review/<int:review_id>/', DeleteReviewAPIView.as_view(), name='admin_delete_review'),
    path('news/', NewsListAPIView.as_view(), name='admin_news_list'),
    path('news/<int:news_id>/', NewsDetailAPIView.as_view(), name='admin_news_detail'),
    path('customer-messages/', CustomerMessagesListAPIView.as_view(), name='admin_customer_messages_list'),
    path('customer-messages/<int:message_id>/', CustomerMessageDetailAPIView.as_view(), name='admin_customer_message_detail'),
]
