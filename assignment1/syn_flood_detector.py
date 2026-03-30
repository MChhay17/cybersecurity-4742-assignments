#!/usr/bin/env python3

import argparse
import csv
import os
import signal
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import sniff, IP, TCP

SYN_THRESHOLD_PER_SECOND = 100
CONSECUTIVE_SECONDS_REQUIRED = 3
HISTORY_LOOKBACK_MINUTES = 30
DEFAULT_ALERT_FILE = "syn_flood_alerts.csv"

# src_ip -> deque of packet timestamps (keep last 10 min max if you want)
syn_packets = defaultdict(deque)

# src_ip -> deque of second buckets where threshold was exceeded
high_rate_seconds = defaultdict(deque)


def parse_args():
    parser = argparse.ArgumentParser(description="SYN flood detector")
    parser.add_argument("-i", "--interface", required=True, help="Interface to listen on, example: eth0")
    parser.add_argument(
        "-a",
        "--alerts",
        default=DEFAULT_ALERT_FILE,
        help="CSV file to store SYN flood alerts"
    )
    return parser.parse_args()


def ensure_alert_csv_exists(alert_file):
    if not os.path.exists(alert_file):
        with open(alert_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "rate_per_sec", "duration_sec"])


def now_dt():
    return datetime.now()


def cleanup_old_syn_packets(src_ip, current_time):
    cutoff = current_time - timedelta(minutes=10)
    dq = syn_packets[src_ip]
    while dq and dq[0] < cutoff:
        dq.popleft()


def count_syns_in_last_second(src_ip, current_time):
    dq = syn_packets[src_ip]
    cutoff = current_time - timedelta(seconds=1)
    count = 0
    for ts in reversed(dq):
        if ts < cutoff:
            break
        count += 1
    return count


def check_previous_alert(src_ip, alert_file, current_time):
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


def write_alert(alert_file, src_ip, rate_per_sec, duration_sec, current_time):
    with open(alert_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            current_time.strftime("%Y-%m-%d %H:%M:%S"),
            src_ip,
            rate_per_sec,
            duration_sec
        ])


def already_recorded_this_second(src_ip, second_mark):
    return second_mark in high_rate_seconds[src_ip]


def cleanup_old_high_rate_seconds(src_ip, current_time):
    cutoff = current_time - timedelta(seconds=10)
    dq = high_rate_seconds[src_ip]
    while dq and dq[0] < cutoff:
        dq.popleft()


def has_3_consecutive_seconds(src_ip):
    seconds_list = list(high_rate_seconds[src_ip])
    if len(seconds_list) < CONSECUTIVE_SECONDS_REQUIRED:
        return False

    # convert to unique sorted seconds
    unique_sorted = sorted(set(seconds_list))
    streak = 1

    for i in range(1, len(unique_sorted)):
        diff = (unique_sorted[i] - unique_sorted[i - 1]).total_seconds()
        if diff == 1:
            streak += 1
            if streak >= CONSECUTIVE_SECONDS_REQUIRED:
                return True
        else:
            streak = 1

    return False


def process_packet(pkt, alert_file):
    if IP not in pkt or TCP not in pkt:
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    # SYN packet only: SYN set, ACK not set
    if not (tcp.flags & 0x02):
        return
    if tcp.flags & 0x10:
        return

    src_ip = ip.src
    current_time = now_dt()

    syn_packets[src_ip].append(current_time)
    cleanup_old_syn_packets(src_ip, current_time)

    rate_1s = count_syns_in_last_second(src_ip, current_time)

    # use second-level bucket
    second_mark = current_time.replace(microsecond=0)
    cleanup_old_high_rate_seconds(src_ip, current_time)

    if rate_1s > SYN_THRESHOLD_PER_SECOND:
        if not already_recorded_this_second(src_ip, second_mark):
            high_rate_seconds[src_ip].append(second_mark)

    if has_3_consecutive_seconds(src_ip):
        previous = check_previous_alert(src_ip, alert_file, current_time)

        print("\nALERT: SYN Flood Detected!")
        print(f"Source: {src_ip} | Rate: {rate_1s} SYN packets/sec | Duration: 3 sec")
        print(f"Previous SYN flood detected in last 30 minutes: {'YES' if previous else 'NO'}")

        write_alert(alert_file, src_ip, rate_1s, 3, current_time)

        # reset a little to avoid spamming duplicate alerts constantly
        high_rate_seconds[src_ip].clear()
        syn_packets[src_ip].clear()


def stop_handler(sig, frame):
    print("\nStopping SYN flood detector...")
    sys.exit(0)


def main():
    args = parse_args()
    ensure_alert_csv_exists(args.alerts)

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    print(f"[*] Starting SYN flood detector on interface: {args.interface}")
    print(f"[*] Alert history file: {args.alerts}")
    print(f"[*] Threshold: > {SYN_THRESHOLD_PER_SECOND} SYN packets/sec")
    print(f"[*] Required duration: {CONSECUTIVE_SECONDS_REQUIRED} consecutive seconds")
    print()

    sniff(iface=args.interface, prn=lambda pkt: process_packet(pkt, args.alerts), store=False)


if __name__ == "__main__":
    main()