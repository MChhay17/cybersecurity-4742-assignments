#!/usr/bin/env python3

import argparse
import csv
import os
import signal
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import sniff, IP, TCP

# ---------------------------
# Assignment thresholds
# ---------------------------
PORTS_PER_SECOND_THRESHOLD = 5
PORTS_PER_MINUTE_THRESHOLD = 100
PORTS_PER_5MIN_THRESHOLD = 300
HISTORY_LOOKBACK_MINUTES = 30

# Files
DEFAULT_ALERT_CSV = "port_scan_alerts.csv"

# Track first-contact attempts:
# (src_ip, src_port, dst_ip, dst_port)
seen_first_contacts = set()

# For each source IP, store (timestamp, dst_port)
per_ip_attempts = defaultdict(deque)

running = True


def parse_args():
    parser = argparse.ArgumentParser(description="Port scan detector using RBS thresholds.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to listen on (example: eth0)")
    parser.add_argument(
        "-a",
        "--alerts",
        default=DEFAULT_ALERT_CSV,
        help="CSV file to store port scan alerts (default: port_scan_alerts.csv)",
    )
    return parser.parse_args()


def ensure_alert_csv_exists(alert_file):
    file_exists = os.path.exists(alert_file)
    if not file_exists:
        with open(alert_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "reason", "fanout_rate"])


def now_dt():
    return datetime.now()


def cleanup_old_attempts(src_ip, current_time):
    window_5min = current_time - timedelta(minutes=5)
    dq = per_ip_attempts[src_ip]
    while dq and dq[0][0] < window_5min:
        dq.popleft()


def count_unique_ports(src_ip, current_time, seconds):
    dq = per_ip_attempts[src_ip]
    cutoff = current_time - timedelta(seconds=seconds)
    ports = set()

    # iterate newest to oldest for speed
    for ts, port in reversed(dq):
        if ts < cutoff:
            break
        ports.add(port)

    return len(ports)


def was_previously_flagged(src_ip, alert_file, current_time):
    if not os.path.exists(alert_file):
        return False

    lookback = current_time - timedelta(minutes=HISTORY_LOOKBACK_MINUTES)

    try:
        with open(alert_file, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    if row["src_ip"] != src_ip:
                        continue
                    ts = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                    if ts >= lookback:
                        return True
                except Exception:
                    continue
    except Exception:
        return False

    return False


def write_alert(alert_file, src_ip, reason, fanout_rate, current_time):
    with open(alert_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            current_time.strftime("%Y-%m-%d %H:%M:%S"),
            src_ip,
            reason,
            fanout_rate
        ])


def process_packet(pkt, alert_file):
    if IP not in pkt or TCP not in pkt:
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    # Count TCP SYN as a connection attempt.
    # SYN set and ACK not set => new connection attempt
    if not (tcp.flags & 0x02):
        return
    if tcp.flags & 0x10:
        return

    src_ip = ip.src
    dst_ip = ip.dst
    src_port = tcp.sport
    dst_port = tcp.dport
    current_time = now_dt()

    # First-contact tracking
    contact_key = (src_ip, src_port, dst_ip, dst_port)
    if contact_key in seen_first_contacts:
        return
    seen_first_contacts.add(contact_key)

    per_ip_attempts[src_ip].append((current_time, dst_port))
    cleanup_old_attempts(src_ip, current_time)

    ports_1s = count_unique_ports(src_ip, current_time, 1)
    ports_60s = count_unique_ports(src_ip, current_time, 60)
    ports_300s = count_unique_ports(src_ip, current_time, 300)

    reason = None
    fanout_rate = None

    if ports_1s > PORTS_PER_SECOND_THRESHOLD:
        reason = f"Exceeded {PORTS_PER_SECOND_THRESHOLD} ports/sec threshold"
        fanout_rate = f"{ports_1s} ports/sec"
    elif ports_60s > PORTS_PER_MINUTE_THRESHOLD:
        reason = f"Exceeded {PORTS_PER_MINUTE_THRESHOLD} ports/min threshold"
        fanout_rate = f"{ports_60s} ports/min"
    elif ports_300s > PORTS_PER_5MIN_THRESHOLD:
        reason = f"Exceeded {PORTS_PER_5MIN_THRESHOLD} ports/5min threshold"
        fanout_rate = f"{ports_300s} ports/5min"

    if reason:
        previous = was_previously_flagged(src_ip, alert_file, current_time)

        print("\nALERT: Port Scanner Detected!")
        print(f"Source: {src_ip} | Fan-Out Rate: {fanout_rate} | Reason: {reason}")
        print(f"Previous port scan detected in last 30 minutes: {'YES' if previous else 'NO'}")

        write_alert(alert_file, src_ip, reason, fanout_rate, current_time)


def stop_handler(sig, frame):
    global running
    running = False
    print("\nStopping port scanner detector...")
    sys.exit(0)


def main():
    args = parse_args()
    ensure_alert_csv_exists(args.alerts)

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    print(f"[*] Starting port scanner detector on interface: {args.interface}")
    print(f"[*] Alert history file: {args.alerts}")
    print("[*] Watching for TCP SYN first-contact attempts...")
    print("[*] Thresholds:")
    print(f"    > {PORTS_PER_SECOND_THRESHOLD} unique ports/sec")
    print(f"    > {PORTS_PER_MINUTE_THRESHOLD} unique ports/min")
    print(f"    > {PORTS_PER_5MIN_THRESHOLD} unique ports/5min")
    print()

    sniff(iface=args.interface, prn=lambda pkt: process_packet(pkt, args.alerts), store=False)


if __name__ == "__main__":
    main()