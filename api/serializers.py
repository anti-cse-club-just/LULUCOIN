from rest_framework import serializers
from .models import LuluCoinBlock, Transaction, CustomUser, GlobalVariables


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'username', 'email', 'city', 'password')


class LuluCoinBlockSerializer(serializers.ModelSerializer):
    class Meta:
        model = LuluCoinBlock
        fields = ('block_hash', 'previous_block_hash', 'transactions', 'timestamp', 'nonce', 'difficulty', 'created_by')


class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ('sender', 'receiver', 'amount', 'signature')


class GlobalVariablesSerializer(serializers.ModelSerializer):
    class Meta:
        model = GlobalVariables
        fields = ('difficulty', 'mining_reward', 'fees')
