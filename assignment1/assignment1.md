# Assignment 1: Network Attack Detection

## 1. Implementation Details

This project implements four components:

- Packet sniffer
- ICMP flood detector
- SYN flood detector
- Port scanner detector

The packet sniffer captures IPv4 packets and logs them into memory and a CSV file. The detectors analyze this data to identify abnormal traffic patterns.

---

## 2. Testing Environment

- Defense Machine: Kali Linux
- Attack Machine: Kali Linux
- Target Machine: Metasploitable 2
- Network: 192.168.10.0/24

Tools used:
- nmap (port scanning)
- hping3 (ICMP and SYN floods)
- ping (normal traffic)

---

## 3. Test Results and Screenshots

### ICMP Normal Test

Command:
```bash
ping <target-ip>
