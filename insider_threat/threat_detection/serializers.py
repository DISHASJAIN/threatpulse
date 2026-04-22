from rest_framework import serializers
from .models import NetworkLog, Alert

class NetworkLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkLog
        fields = '__all__'

class AlertSerializer(serializers.ModelSerializer):
    log = NetworkLogSerializer(read_only=True)

    class Meta:
        model = Alert
        fields = '__all__'