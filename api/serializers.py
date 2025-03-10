from rest_framework import serializers
from .models import LuluCoinBlock


class LuluCoinBlockSerializer(serializers.ModelSerializer):
    class Meta:
        model = LuluCoinBlock
        fields = ('transactions', 'created_by')
        