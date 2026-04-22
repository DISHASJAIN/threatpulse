from celery import shared_task
from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np
from .models import NetworkLog, Alert

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

@shared_task
def run_anomaly_detection():
    logs = NetworkLog.objects.filter(is_anomalous=False).values(
        'id', 'packet_length', 'source_port', 'destination_port', 'anomaly_score'
    )
    if not logs:
        return "No new logs to process"

    df = pd.DataFrame(list(logs))
    features = df[['packet_length', 'source_port', 'destination_port']].fillna(0)

    model = IsolationForest(contamination=0.05, random_state=42)
    predictions = model.fit_predict(features)
    scores = model.decision_function(features)

    for i, log_id in enumerate(df['id']):
        is_anomaly = predictions[i] == -1

        NetworkLog.objects.filter(id=log_id).update(
            is_anomalous=is_anomaly,
            anomaly_score=round(float(scores[i]), 4)
        )

        if is_anomaly:
            log = NetworkLog.objects.get(id=log_id)

            alert = Alert.objects.create(
                log=log,
                message=f"Anomaly detected from {log.source_ip} — score: {scores[i]:.3f}",
                severity='Critical' if scores[i] < -0.5 else 'High' if scores[i] < -0.2 else 'Medium' if scores[i] < -0.05 else 'Low'
            )

            # 🔥 REAL-TIME ALERT
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "alerts_group",
                {
                    "type": "send_alert",
                    "message": alert.message,
                    "severity": alert.severity
                }
            )

    return f"Processed {len(df)} logs"