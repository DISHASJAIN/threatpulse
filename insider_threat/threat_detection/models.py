from django.db import models

class NetworkLog(models.Model):
    timestamp = models.DateTimeField()
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    packet_length = models.IntegerField()
    packet_type = models.CharField(max_length=50)
    traffic_type = models.CharField(max_length=50)
    anomaly_score = models.FloatField(null=True, blank=True)
    attack_type = models.CharField(max_length=100, blank=True)
    severity_level = models.CharField(max_length=20, blank=True)
    user_information = models.CharField(max_length=200, blank=True)
    network_segment = models.CharField(max_length=50, blank=True)
    is_anomalous = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

     # Blockchain fields         ← ADD THESE TWO
    log_hash = models.CharField(max_length=64, blank=True)
    prev_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ['-timestamp']


class Alert(models.Model):
    SEVERITY = [('Low','Low'),('Medium','Medium'),('High','High'),('Critical','Critical')]

    log = models.ForeignKey(NetworkLog, on_delete=models.CASCADE, related_name='alerts')
    message = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY)
    created_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)


class LoginAuditLog(models.Model):
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        status = 'SUCCESS' if self.success else 'FAILED'
        return f"{status} — {self.username} @ {self.ip_address}"