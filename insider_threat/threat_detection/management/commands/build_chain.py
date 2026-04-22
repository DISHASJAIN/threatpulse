from django.core.management.base import BaseCommand
from threat_detection.models import NetworkLog
from threat_detection.blockchain import build_hash_chain


class Command(BaseCommand):
    help = 'Build blockchain hash chain for all logs'

    def handle(self, *args, **options):
        self.stdout.write('Building hash chain...')
        logs = NetworkLog.objects.all().order_by('id')
        total = build_hash_chain(logs)
        self.stdout.write(self.style.SUCCESS(
            f'Hash chain built for {total} logs!'
        ))