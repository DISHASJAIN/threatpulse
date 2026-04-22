import hashlib
import json
from datetime import datetime


def compute_log_hash(log, prev_hash="0" * 64):
    """
    Compute SHA-256 hash for a log entry.
    Each hash includes the previous hash — this is the chain.
    """
    data = {
        'id':          log.id,
        'timestamp':   str(log.timestamp),
        'source_ip':   log.source_ip,
        'dest_ip':     log.destination_ip,
        'protocol':    log.protocol,
        'packet_len':  log.packet_length,
        'attack_type': log.attack_type,
        'anomaly':     log.is_anomalous,
        'prev_hash':   prev_hash,
    }
    raw = json.dumps(data, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def build_hash_chain(logs):
    """
    Given a queryset of logs ordered by id,
    compute and save the hash chain for all of them.
    """
    prev_hash = "0" * 64
    updated = 0

    for log in logs:
        h = compute_log_hash(log, prev_hash)
        log.log_hash = h
        log.prev_hash = prev_hash
        log.save(update_fields=['log_hash', 'prev_hash'])
        prev_hash = h
        updated += 1

    return updated


def verify_chain(logs):
    """
    Verify the integrity of the hash chain.
    Returns list of results — each entry shows if the log is valid or tampered.
    """
    results = []
    prev_hash = "0" * 64

    for log in logs:
        expected = compute_log_hash(log, prev_hash)
        is_valid = (log.log_hash == expected)
        results.append({
            'id':         log.id,
            'timestamp':  log.timestamp,
            'source_ip':  log.source_ip,
            'attack_type':log.attack_type,
            'log_hash':   log.log_hash,
            'prev_hash':  log.prev_hash,
            'is_valid':   is_valid,
            'status':     'VERIFIED' if is_valid else 'TAMPERED',
        })
        prev_hash = log.log_hash

    return results