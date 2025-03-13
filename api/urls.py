from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views


urlpatterns = [
    path('info/', views.InfoView.as_view(), name='intro'),
    path('token/', TokenObtainPairView.as_view(), name='get-token'),
    path('token/refresh/', TokenRefreshView.as_view(), name='refresh-token'),
    path('global-variables/', views.GlobalVariablesView.as_view(), name='global-variables-adjustments'),
    path('register/', views.CustomRegister.as_view(), name='register'),
    path('transactions/', views.TransactionView.as_view(), name="transaction-hadling"),
    path('add-block/', views.AddBlockView.as_view(), name='add-new-block'),
    path('validate-blockchain/', views.ValidateView.as_view(), name='validate-bolckchain'),
]
