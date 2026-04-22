from django.core.management.base import BaseCommand
import pandas as pd
from threat_detection.models import NetworkLog
from django.utils.dateparse import parse_datetime
import numpy as np

class Command(BaseCommand):
    help = 'Import network logs from CSV file'

    def add_arguments(self, parser):
        parser.add_argument('csv_path', type=str, help='Path to CSV file')

    def handle(self, *args, **options):
        path = options['csv_path']
        self.stdout.write(f'Reading {path}...')

        df = pd.read_csv(path)
        df.columns = df.columns.str.strip()
        df = df.where(pd.notnull(df), None)  # convert NaN to None

        logs = []
        skipped = 0

        for _, row in df.iterrows():
            try:
                logs.append(NetworkLog(
                    timestamp=parse_datetime(str(row.get('Timestamp', '')).strip()),
                    source_ip=str(row.get('Source IP Address', '0.0.0.0')).strip(),
                    destination_ip=str(row.get('Destination IP Address', '0.0.0.0')).strip(),
                    source_port=int(row.get('Source Port', 0) or 0),
                    destination_port=int(row.get('Destination Port', 0) or 0),
                    protocol=str(row.get('Protocol', '') or ''),
                    packet_length=int(row.get('Packet Length', 0) or 0),
                    packet_type=str(row.get('Packet Type', '') or ''),
                    traffic_type=str(row.get('Traffic Type', '') or ''),
                    anomaly_score=float(row.get('Anomaly Scores', 0) or 0),
                    attack_type=str(row.get('Attack Type', '') or ''),
                    severity_level=str(row.get('Severity Level', '') or ''),
                    user_information=str(row.get('User Information', '') or ''),
                    network_segment=str(row.get('Network Segment', '') or ''),
                ))
            except Exception as e:
                skipped += 1

        NetworkLog.objects.bulk_create(logs, ignore_conflicts=True)
        self.stdout.write(self.style.SUCCESS(
            f'Imported {len(logs)} logs. Skipped {skipped} rows.'
        ))