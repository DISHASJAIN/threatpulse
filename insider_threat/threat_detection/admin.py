from django.contrib import admin
from .models import NetworkLog, Alert

@admin.register(NetworkLog)
class NetworkLogAdmin(admin.ModelAdmin):
    list_display = [
        'timestamp', 'source_ip', 'destination_ip',
        'protocol', 'attack_type', 'severity_level',
        'is_anomalous', 'user_information'
    ]
    list_filter = [
        'is_anomalous', 'severity_level',
        'attack_type', 'protocol'
    ]
    search_fields = [
        'source_ip', 'destination_ip',
        'user_information', 'attack_type'
    ]
    ordering = ['-timestamp']
    readonly_fields = ['is_anomalous', 'created_at']

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['created_at', 'severity', 'message', 'is_resolved']
    list_filter = ['severity', 'is_resolved']
    search_fields = ['message']
    ordering = ['-created_at']