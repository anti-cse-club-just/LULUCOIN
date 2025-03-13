from django.contrib import admin
from .models import LuluCoinBlock, Transaction, CustomUser, GlobalVariables


admin.site.register(GlobalVariables)
admin.site.register(LuluCoinBlock)
admin.site.register(Transaction)
admin.site.register(CustomUser)
