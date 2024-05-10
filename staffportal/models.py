from django.db import models
from django.contrib.auth.models import AbstractUser
from customerportal.models import LoanApplication
from django.conf import settings



class CustomUser(AbstractUser):
    first_name= models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=255,unique=True)
    staff = models.BooleanField(default=False)
    blocked = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username','first_name','last_name']

    def __str__(self):
        return self.username


class BankAccount(models.Model):
    accname = models.CharField(max_length=100, null=True, blank=True)
    accdesc = models.CharField(max_length=2500, null=True, blank=True)
    acciamge = models.ImageField(upload_to='Images', null=True, blank=True)

    def __str__(self):
        return self.accname


class FDAndRDInterestRate(models.Model):
    rate = models.DecimalField(max_digits=5, decimal_places=2)   


class LoanInterestRate(models.Model):
    LOAN_TYPES = [
        ('Personal Loan', 'Personal Loan'),
        ('Home Loan', 'Home Loan'),
        ('Car Loan', 'Car Loan'),
        ('Education Loan', 'Education Loan'),

    ]

    loan_type = models.CharField(max_length=100, choices=LOAN_TYPES)
    rate = models.DecimalField(max_digits=5, decimal_places=2)



class LoanApproval(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    approved_date = models.DateField(auto_now_add=True)
    new_status = models.CharField(max_length=20, choices=LoanApplication.STATUS_CHOICES, default='Approved')

    def __str__(self):
        return f"{self.user.username} - {self.approved_date}"




class BankNews(models.Model):
    title = models.CharField(max_length=100, null=True, blank=True)
    short_description = models.CharField(max_length=2000, null=True, blank=True)
    full_description = models.CharField(max_length=3000, null=True, blank=True)
    news_image = models.ImageField(upload_to='Images', null=True, blank=True)
    created_at = models.DateField(auto_now_add=True)