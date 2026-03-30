import argparse
import csv
import os
import time
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, ICMP

packet_buffer = deque()
csv_buffer = []
CSV_WRITE_INTERVAL = 10
last_write_time = time.time()
args = None


def tcp_flags_to_string(flags):
    flag_names = []
    if flags & 0x02:
        flag_names.append("SYN")
    if flags & 0x10:
        flag_names.append("ACK")
    if flags & 0x01:
        flag_names.append("FIN")
    if flags & 0x04:
        flag_names.append("RST")
    if flags & 0x08:
        flag_names.append("PSH")
    if flags & 0x20:
        flag_names.append("URG")
    return "|".join(flag_names) if flag_names else ""


def write_to_csv():
    global csv_buffer
    if not args.output or not csv_buffer:
        return

    with open(args.output, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(csv_buffer)

    csv_buffer.clear()


def process_packet(packet):
    global last_write_time

    if IP not in packet:
        return

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dst_port = ""
    protocol = ""
    tcp_flags = ""

    if TCP in packet:
        protocol = "TCP"
        dst_port = packet[TCP].dport
        tcp_flags = tcp_flags_to_string(packet[TCP].flags)
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

    entry = [timestamp, src_ip, dst_ip, dst_port, protocol, tcp_flags]
    print(entry)

    current_time = time.time()
    packet_buffer.append((current_time, entry))
    csv_buffer.append(entry)

    while packet_buffer and current_time - packet_buffer[0][0] > 600:
        packet_buffer.popleft()

    if current_time - last_write_time >= CSV_WRITE_INTERVAL:
        write_to_csv()
        last_write_time = current_time


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IPv4 Packet Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-o", "--output", help="CSV output file")
    args = parser.parse_args()

    if args.output and not os.path.exists(args.output):
        with open(args.output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "tcp_flags"])

    print(f"[+] Sniffing on interface: {args.interface}")
    print("[+] Press Ctrl+C to stop")

    try:
        sniff(iface=args.interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[+] Stopping sniffer...")
        write_to_csv()
        print("[+] Remaining packets written to CSV.")