from django.contrib import admin

from staffportal.models import CustomUser, LoanInterestRate, LoanApproval

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(LoanInterestRate)
admin.site.register(LoanApproval)
