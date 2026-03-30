#!/usr/bin/env python3

import argparse
import csv
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import sniff, IP, TCP

# =========================================================
# Configuration constants
# =========================================================
SYN_THRESHOLD_PER_SEC = 100
CONSECUTIVE_SECONDS_REQUIRED = 3
HISTORY_LOOKBACK_MINUTES = 30

DEBUG = True

# =========================================================
# Global data structures
# =========================================================
# Count SYN packets per source IP per second
# per_second_counts[src_ip][unix_second] = count
per_second_counts = defaultdict(lambda: defaultdict(int))

# Number of consecutive "bad" seconds for each source IP
consecutive_bad_seconds = defaultdict(int)

# Last second seen for each source IP
last_seen_second = {}

# Recent alert timestamps stored in memory
recent_alerts = defaultdict(deque)

# Prevent repeated alert spam
last_alert_time = {}

# =========================================================
# Helper functions
# =========================================================
def debug_print(message):
    if DEBUG:
        print(message)


def current_time_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_csv_exists(csv_file):
    """
    Create the alert history CSV if it does not already exist.
    """
    if not os.path.exists(csv_file):
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "rate", "duration_seconds"])


def append_alert_to_csv(csv_file, src_ip, rate, duration):
    """
    Save the alert to the CSV history file.
    """
    with open(csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([current_time_str(), src_ip, rate, duration])


def load_recent_alerts_from_csv(csv_file):
    """
    Load alerts from the CSV file that occurred within the last 30 minutes.
    """
    if not os.path.exists(csv_file):
        return

    cutoff = datetime.now() - timedelta(minutes=HISTORY_LOOKBACK_MINUTES)

    with open(csv_file, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                alert_time = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                src_ip = row["src_ip"]

                if alert_time >= cutoff:
                    recent_alerts[src_ip].append(alert_time)

            except (KeyError, ValueError):
                continue


def cleanup_old_alerts():
    """
    Remove alert timestamps older than 30 minutes from memory.
    """
    cutoff = datetime.now() - timedelta(minutes=HISTORY_LOOKBACK_MINUTES)

    for src_ip in list(recent_alerts.keys()):
        while recent_alerts[src_ip] and recent_alerts[src_ip][0] < cutoff:
            recent_alerts[src_ip].popleft()

        if not recent_alerts[src_ip]:
            del recent_alerts[src_ip]


def had_previous_alert_in_last_30_minutes(src_ip):
    """
    Return True if this IP already had an alert in the last 30 minutes.
    """
    cleanup_old_alerts()
    return len(recent_alerts[src_ip]) > 0


def cleanup_old_packet_counts(src_ip, now_second):
    """
    Remove old counters to keep memory usage small.
    """
    old_seconds = [sec for sec in per_second_counts[src_ip] if sec < now_second - 5]
    for sec in old_seconds:
        del per_second_counts[src_ip][sec]


def is_syn_packet(packet):
    """
    Return True only for pure TCP SYN packets.
    SYN=1 and ACK=0
    """
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return False

    tcp_layer = packet[TCP]
    return tcp_layer.flags == "S"


def process_completed_second(src_ip, completed_second, alert_csv):
    """
    Evaluate one completed second for a given source IP.
    """
    previous_count = per_second_counts[src_ip].get(completed_second, 0)

    debug_print(
        f"[DEBUG] {src_ip} sent {previous_count} SYN packets during second {completed_second}"
    )

    if previous_count > SYN_THRESHOLD_PER_SEC:
        consecutive_bad_seconds[src_ip] += 1
        debug_print(
            f"[DEBUG] Threshold exceeded for {src_ip}. "
            f"Consecutive bad seconds = {consecutive_bad_seconds[src_ip]}"
        )
    else:
        consecutive_bad_seconds[src_ip] = 0

    if consecutive_bad_seconds[src_ip] >= CONSECUTIVE_SECONDS_REQUIRED:
        previous_flood_found = had_previous_alert_in_last_30_minutes(src_ip)

        debug_print(f"[DEBUG] 3-second SYN flood condition met for {src_ip}")
        debug_print(
            f"[DEBUG] Previous SYN flood in last {HISTORY_LOOKBACK_MINUTES} minutes: "
            f"{'YES' if previous_flood_found else 'NO'}"
        )

        now_dt = datetime.now()
        already_alerted_recently = (
            src_ip in last_alert_time and
            (now_dt - last_alert_time[src_ip]).total_seconds() < 10
        )

        if not already_alerted_recently:
            print("\nALERT: SYN Flood Detected!")
            print(
                f"Source: {src_ip} | Rate: {previous_count} SYN packets/sec | "
                f"Duration: {CONSECUTIVE_SECONDS_REQUIRED} sec"
            )
            print(
                f"Previous SYN flood detected in last {HISTORY_LOOKBACK_MINUTES} minutes: "
                f"{'YES' if previous_flood_found else 'NO'}"
            )
            print("-" * 60)

            append_alert_to_csv(
                alert_csv,
                src_ip,
                previous_count,
                CONSECUTIVE_SECONDS_REQUIRED
            )

            recent_alerts[src_ip].append(now_dt)
            last_alert_time[src_ip] = now_dt


def parse_packet(packet, alert_csv):
    """
    Process each sniffed packet.
    Only pure TCP SYN packets are counted.
    """
    if not is_syn_packet(packet):
        return

    ip_layer = packet[IP]
    tcp_layer = packet[TCP]

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    dst_port = tcp_layer.dport
    now_second = int(time.time())

    debug_print(f"[DEBUG] SYN packet seen: {src_ip} -> {dst_ip}:{dst_port}")

    if src_ip not in last_seen_second:
        last_seen_second[src_ip] = now_second

    if now_second != last_seen_second[src_ip]:
        if now_second - last_seen_second[src_ip] > 1:
            consecutive_bad_seconds[src_ip] = 0

        process_completed_second(src_ip, last_seen_second[src_ip], alert_csv)
        last_seen_second[src_ip] = now_second

    per_second_counts[src_ip][now_second] += 1
    cleanup_old_packet_counts(src_ip, now_second)


def start_sniffer(interface, alert_csv):
    """
    Start packet sniffing on the selected interface.
    """
    print(f"[*] Starting SYN flood detector on interface: {interface}")
    print(f"[*] Threshold: > {SYN_THRESHOLD_PER_SEC} SYN packets/sec")
    print(f"[*] Consecutive seconds required: {CONSECUTIVE_SECONDS_REQUIRED}")
    print(f"[*] Historical lookback: {HISTORY_LOOKBACK_MINUTES} minutes")
    print(f"[*] Alert history file: {alert_csv}")
    print("[*] Waiting for TCP SYN traffic...\n")

    sniff(
        iface=interface,
        prn=lambda pkt: parse_packet(pkt, alert_csv),
        store=False
    )


def main():
    parser = argparse.ArgumentParser(description="SYN Flood Detector")
    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Network interface to listen on (example: eth0)"
    )
    parser.add_argument(
        "-a", "--alert-file",
        default="syn_flood_alerts.csv",
        help="CSV file to store SYN flood alert history"
    )
    parser.add_argument(
        "--no-debug",
        action="store_true",
        help="Disable debug output"
    )

    args = parser.parse_args()

    global DEBUG
    if args.no_debug:
        DEBUG = False

    ensure_csv_exists(args.alert_file)
    load_recent_alerts_from_csv(args.alert_file)
    start_sniffer(args.interface, args.alert_file)


if __name__ == "__main__":
    main()