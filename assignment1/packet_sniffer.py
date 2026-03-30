#!/usr/bin/env python3

import argparse
import csv
import os
import signal
import sys
import threading
import time
from collections import deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP


# Keep only the last 10 minutes of packets in memory
MEMORY_WINDOW_SECONDS = 600

# Flush buffered CSV rows every 10 seconds
CSV_FLUSH_INTERVAL = 10

# Shared data structures
packet_memory = deque()
csv_buffer = []

# Lock for thread-safe access
data_lock = threading.Lock()

# Global control flag
running = True


def parse_args():
    parser = argparse.ArgumentParser(description="IPv4 Packet Sniffer for Assignment 1")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to listen on")
    parser.add_argument("-o", "--output", help="CSV output file")
    return parser.parse_args()


def format_tcp_flags(tcp_flags):
    flags = []

    if tcp_flags & 0x01:
        flags.append("FIN")
    if tcp_flags & 0x02:
        flags.append("SYN")
    if tcp_flags & 0x04:
        flags.append("RST")
    if tcp_flags & 0x08:
        flags.append("PSH")
    if tcp_flags & 0x10:
        flags.append("ACK")
    if tcp_flags & 0x20:
        flags.append("URG")
    if tcp_flags & 0x40:
        flags.append("ECE")
    if tcp_flags & 0x80:
        flags.append("CWR")

    return "|".join(flags) if flags else ""


def ensure_csv_header(csv_file):
    if not csv_file:
        return

    file_exists = os.path.exists(csv_file)
    if not file_exists or os.path.getsize(csv_file) == 0:
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "tcp_flags"])


def flush_csv(csv_file):
    global csv_buffer

    if not csv_file:
        return

    with data_lock:
        if not csv_buffer:
            return

        rows_to_write = csv_buffer[:]
        csv_buffer.clear()

    with open(csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows_to_write)


def csv_flush_worker(csv_file):
    global running
    while running:
        time.sleep(CSV_FLUSH_INTERVAL)
        flush_csv(csv_file)


def cleanup_old_packets():
    current_time = time.time()

    with data_lock:
        while packet_memory and (current_time - packet_memory[0]["epoch"]) > MEMORY_WINDOW_SECONDS:
            old_packet = packet_memory.popleft()
            csv_buffer.append([
                old_packet["timestamp"],
                old_packet["src_ip"],
                old_packet["dst_ip"],
                old_packet["dst_port"],
                old_packet["protocol"],
                old_packet["tcp_flags"]
            ])


def process_packet(packet):
    if IP not in packet:
        return

    ip_layer = packet[IP]

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    protocol = ""
    dst_port = ""
    tcp_flags = ""

    if TCP in packet:
        protocol = "TCP"
        dst_port = packet[TCP].dport
        tcp_flags = format_tcp_flags(packet[TCP].flags)
    elif UDP in packet:
        protocol = "UDP"
        dst_port = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"
        icmp_type = packet[ICMP].type
        if icmp_type == 8:
            tcp_flags = "ECHO_REQUEST"
        elif icmp_type == 0:
            tcp_flags = "ECHO_REPLY"
        else:
            tcp_flags = f"TYPE_{icmp_type}"
    else:
        return

    packet_record = {
        "epoch": time.time(),
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "tcp_flags": tcp_flags
    }

    with data_lock:
        packet_memory.append(packet_record)

    cleanup_old_packets()

    print(f"{timestamp}, {src_ip}, {dst_ip}, {dst_port}, {protocol}, {tcp_flags}")


def handle_exit(signum, frame):
    global running
    running = False
    print("\nStopping sniffer... flushing remaining logs.")
    raise KeyboardInterrupt


def main():
    args = parse_args()

    if args.output:
        ensure_csv_header(args.output)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    flush_thread = None
    if args.output:
        flush_thread = threading.Thread(target=csv_flush_worker, args=(args.output,), daemon=True)
        flush_thread.start()

    print(f"[*] Sniffing on interface: {args.interface}")
    if args.output:
        print(f"[*] CSV logging enabled: {args.output}")
    else:
        print("[*] CSV logging disabled. Printing only.")

    print("[*] Press Ctrl+C to stop.\n")
    print("timestamp, src_ip, dst_ip, dst_port, protocol, tcp_flags")

    try:
        sniff(iface=args.interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        if args.output:
            with data_lock:
                while packet_memory:
                    pkt = packet_memory.popleft()
                    csv_buffer.append([
                        pkt["timestamp"],
                        pkt["src_ip"],
                        pkt["dst_ip"],
                        pkt["dst_port"],
                        pkt["protocol"],
                        pkt["tcp_flags"]
                    ])

            flush_csv(args.output)

        print("[*] Sniffer stopped cleanly.")


if __name__ == "__main__":
    main()