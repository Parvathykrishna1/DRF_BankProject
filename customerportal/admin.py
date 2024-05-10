from django.contrib import admin
from customerportal.models import Savings, LoanApplication, CustomerMessages


admin.site.register(Savings)
admin.site.register(LoanApplication)
admin.site.register(CustomerMessages)