from django.db import models
from django.conf import settings
import random
import string
from django.utils import timezone
from django.core.mail import send_mail


# Create your models here.
class Savings(models.Model):
    SAVINGS = "SAVINGS"
    CURRENT = "CURRENT"

    ACCOUNT_TYPES = [
        (SAVINGS, "Savings"),
        (CURRENT, "Current"),
    ]

    SAVINGS_TRANSACTION_LIMIT = 70000

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    aadhar_number = models.CharField(max_length=12, unique=True, default=0)
    phone_number = models.CharField(max_length=10, unique=True, default=0)
    account_number = models.CharField(max_length=10, unique=True, default=0)
    account_type = models.CharField(max_length=10, choices=ACCOUNT_TYPES)
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.account_number:
            self.account_number = self.generate_account_number()
        super().save(*args, **kwargs)

    def generate_account_number(self):
        return "".join(random.choices(string.digits, k=10))

    def deposit(self, amount, description=None):
        if amount <= 0:
            raise ValueError("Amount must be positive")
        if (
            self.account_type == self.SAVINGS
            and amount > self.SAVINGS_TRANSACTION_LIMIT
        ):
            raise ValueError(
                "Deposit amount exceeds maximum transaction limit for savings accounts"
            )
        self.balance += amount
        self.save()

        if self.account_type == self.SAVINGS:
            SavingsTransaction.objects.create(
                account=self,
                transaction_type="DEPOSIT",
                amount=amount,
                description=description,
                date=timezone.now(),
            )
        elif self.account_type == self.CURRENT:
            CurrentTransaction.objects.create(
                account=self,
                transaction_type="DEPOSIT",
                amount=amount,
                description=description,
                date=timezone.now(),
            )

    def withdraw(self, amount, description=None):
        if amount <= 0:
            raise ValueError("Amount must be positive")
        if amount > self.balance:
            raise ValueError("Insufficient funds")
        if (
            self.account_type == self.SAVINGS
            and amount > self.SAVINGS_TRANSACTION_LIMIT
        ):
            raise ValueError(
                "Withdrawal amount exceeds maximum transaction limit for savings accounts"
            )
        self.balance -= amount
        self.save()

        if self.account_type == self.SAVINGS:
            SavingsTransaction.objects.create(
                account=self,
                transaction_type="WITHDRAWAL",
                amount=amount,
                description=description,
                date=timezone.now(),
            )
        elif self.account_type == self.CURRENT:
            CurrentTransaction.objects.create(
                account=self,
                transaction_type="WITHDRAWAL",
                amount=amount,
                description=description,
                date=timezone.now(),
            )


class SavingsTransaction(models.Model):
    DEPOSIT = "DEPOSIT"
    WITHDRAWAL = "WITHDRAWAL"

    TRANSACTION_TYPES = [
        (DEPOSIT, "Deposit"),
        (WITHDRAWAL, "Withdrawal"),
    ]
    account = models.ForeignKey(
        Savings, on_delete=models.CASCADE, related_name="saving_transactions"
    )
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    date = models.DateTimeField(default=timezone.now)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.transaction_type} of {self.amount} on {self.date}"


class CurrentTransaction(models.Model):
    DEPOSIT = "DEPOSIT"
    WITHDRAWAL = "WITHDRAWAL"

    TRANSACTION_TYPES = [
        (DEPOSIT, "Deposit"),
        (WITHDRAWAL, "Withdrawal"),
    ]
    account = models.ForeignKey(
        Savings, on_delete=models.CASCADE, related_name="current_transactions"
    )
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    date = models.DateTimeField(default=timezone.now)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.transaction_type} of {self.amount} on {self.date}"


class FixedDeposit(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    duration_months = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    end_date = models.DateField(null=True, blank=True)
    total_amount = models.DecimalField(
        max_digits=15, decimal_places=2, null=True, blank=True
    )

    def __str__(self):
        return f"Fixed Deposit of {self.amount} for {self.user.username}"


FREQUENCY_CHOICES = [
    ("MONTHLY", "Monthly"),
    ("QUARTERLY", "Quarterly"),
    ("HALF_YEARLY", "Half-Yearly"),
    ("YEARLY", "Yearly"),
]


class RecurrentDeposit(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    end_date = models.DateField(null=True, blank=True)
    total_amount = models.DecimalField(
        max_digits=15, decimal_places=2, null=True, blank=True
    )

    def __str__(self):
        return f"Recurrent Deposit of {self.amount} for {self.user.username}"


class FundTransfer(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, default=True
    )
    sender_account_number = models.CharField(max_length=10)
    receiver_account_number = models.CharField(max_length=10)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)


class LoanApplication(models.Model):
    LOAN_TYPES = [
        ("Personal Loan", "Personal Loan"),
        ("Home Loan", "Home Loan"),
        ("Car Loan", "Car Loan"),
        ("Education Loan", "Education Loan"),
    ]

    STATUS_CHOICES = [
        ("Pending", "Pending"),
        ("Approved", "Approved"),
        ("Rejected", "Rejected"),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    loan_type = models.CharField(max_length=100, choices=LOAN_TYPES)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    duration_months = models.IntegerField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="Pending")
    applied_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.loan_type} Application"


class ReviewRatingDb(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    rating = models.FloatField()
    status = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.subject


class CustomerMessages(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    email = models.EmailField(max_length=100, blank=True, null=True)
    phone_number = models.CharField(max_length=100, blank=True, null=True)
    message = models.CharField(max_length=100, blank=True, null=True)


class Budget(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    category_name = models.CharField(max_length=100)
    allotted_budget = models.DecimalField(max_digits=10, decimal_places=2)
    start_date = models.DateField(auto_now_add=True)
    end_date = models.DateField()

    def __str__(self):
        return f"{self.user.username} - {self.category_name} - ${self.allotted_budget} - {self.start_date} to {self.end_date}"


class Expense(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    budget = models.ForeignKey(
        Budget, on_delete=models.CASCADE
    )  # Connect expense to budget
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField()
    date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.budget.category_name} - ${self.amount}"


class SavingsGoal(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    goal_name = models.CharField(max_length=100)
    target_amount = models.DecimalField(max_digits=10, decimal_places=2)
    current_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    def update_progress(self, amount):
        self.current_amount += amount
        if self.current_amount >= self.target_amount:
            self.completed = True
            # Notify user that the savings goal has been reached
            self.send_notification()
        self.save()

    def send_notification(self):
        subject = f"Savings Goal Completed: {self.name}"
        message = (
            f"Congratulations! Your savings goal '{self.name}' has been completed."
        )
        from_email = "your_email@example.com"
        to_email = [self.user.email]
        send_mail(subject, message, from_email, to_email)
