# Assignment 1: Network Attack Detection  
**CSCY 4742 – Cybersecurity Programming and Analytics (Spring 2026)**  
**Total Points: 100**

---

## Objective
Develop Python-based tools to detect:
- ICMP Flooding
- SYN Flooding
- Port Scanning

### Explanation
In this assignment, I worked on building different network detection tools using Python to identify common attacks like ICMP floods, SYN floods, and port scanning. The goal was to understand how these attacks behave on a network and how they can be detected in real time using packet analysis and logging techniques.

---

## Network Setup
- 3 VMs in LAN (`192.168.10.0/24`)
  - Defense Machine (Kali Linux)
  - Attack Machine (Kali Linux)
  - Target Machine (Metasploitable 2)
- Enable **promiscuous mode** on defense machine (`eth0`)

Screenshot: 
![Enabled Promiscous Mode + Created Packet Sniffer.py](./screenshots/assignment1_pt1_1) 
![Sniffer Running](./screenshots/assignment1_pt1_2) 

### Explanation
For Part 1, I created packet_sniffer.py in Python using Scapy. The program captures IPv4 traffic on the Defense Machine’s network interface running in promiscuous mode. It extracts the timestamp, source IP, destination IP, destination port, protocol, and TCP flags for each TCP, UDP, or ICMP packet. Recent packets are stored in a deque for 10 minutes to support real-time analysis, while older packets are moved into a CSV buffer and written to disk in batches every 10 seconds. This design reduces memory growth and avoids excessive disk writes while preparing the system for later ICMP flood, SYN flood, and port scan detection.

---

# Part 1: Packet Sniffer Extension (10 pts)

## Description
Capture all IPv4 traffic for analysis.

## Requirements
- Timestamp  
- Source IP  
- Destination IP  
- Destination Port  
- Protocol (TCP, UDP, ICMP)  
- TCP Flags  

## Logging
- Store last 10 minutes (deque)
- Batch write to CSV

## Run
python3 packet_sniffer.py -i eth0 -o traffic_log.csv  

Screenshot: 
![Ran Packet Sniffer](./screenshots/assignment1_pt1_4) 

### Explanation
For this part, I extended my packet sniffer to capture all IPv4 traffic and log important fields like source IP, destination IP, and protocol type. I used a deque to store only the last 10 minutes of traffic so the system would not run out of memory. I also implemented batch writing to a CSV file to make logging more efficient and avoid excessive disk writes.

---

## Testing & Screenshots

### Test 1: ICMP Ping
Command:
ping 192.168.56.101

Screenshot:
- Ping command running
- Sniffer output showing ICMP packets
![ICPM Ping](./screenshots/assignment1_pt1_3) 


### Explanation
This test verifies that the sniffer correctly captures ICMP packets. I used a simple ping command and confirmed that the packets appeared in the logs.

---

### Test 2: Port Scan
Command:
nmap -p 22,80,443 192.168.56.101

Screenshot:
- Nmap output
- Sniffer logs showing SYN packets
![Nmap: Port Scan](./screenshots/assignment1_pt1_5) 
![Nmap: Port Scan](./screenshots/assignment1_pt1_6) 

### Explanation
When I tried running the SYN scan on the Metasploitable machine (192.168.56.101), I didn’t see any SYN packets in my sniffer. This is probably because the target machine wasn’t responding properly or the ports were filtered. To fix this, I ran the scan on the Defense machine (192.168.56.102) instead. That worked because it generated clear SYN packets, and I was able to confirm that my sniffer correctly detects TCP SYN traffic.

---

### Test 3: SYN Flood
Command:
sudo hping3 -S -p 80 -i u1000 192.168.56.102

Screenshot:
- Sniffer showing high SYN traffic
![SYN Flood](./screenshots/assignment1_pt1_7) 
![SYN Flood](./screenshots/assignment1_pt1_8) 

### Explanation
This test simulates a SYN flood attack. I verified that the sniffer captured a large number of SYN packets, which will be used in later parts for detection.

---

# Part 2: ICMP Flood Detection (15 pts)

## Detection Criteria
- >50 ICMP/sec  
- Sustained 3 seconds  
- Previous detection in last 30 min  

## Run
python3 icmp_flood_detector.py -i eth0  

Screenshot: 
![ICMP Flood Detector](./screenshots/assignment1_pt1_9)

### Explanation
In this part, I built a detector that monitors ICMP traffic and identifies flooding behavior based on packet rate. The detector tracks how many ICMP requests each IP sends per second and triggers an alert if it exceeds the threshold for a sustained period. I also added a check using the CSV logs to identify repeat attackers.

---

## Testing & Screenshots

### Test 1: Normal Traffic
Command:
ping -c 5 192.168.56.102 

Screenshot:
- Ping output
- No alert from detector
![ICMP Flood Detector](./screenshots/assignment1_pt1_10)
![ICMP Flood Detector](./screenshots/assignment1_pt1_9)

### Explanation
This test ensures that normal ICMP traffic does not trigger false positives. The detector correctly ignored regular ping activity.

---

### Test 2: ICMP Flood Attack
Command:
sudo hping3 -1 --flood 192.168.56.102

Screenshot:
- Attack command
- Detector alert output
![Attack Command](./screenshots/assignment1_pt1_11)
![Detector Alert](./screenshots/assignment1_pt1_12)


### Explanation
This test simulates an ICMP flood attack. The detector successfully identified the high rate of ICMP packets and triggered an alert after the threshold conditions were met.

---

# Part 3: SYN Flood Detection (20 pts)

## Detection Criteria
- >100 SYN/sec  
- Sustained 3 seconds  
- Previous detection in last 30 min  

## Run
python3 syn_flood_detector.py -i eth0  

### Explanation
For this part, I implemented a SYN flood detector that tracks TCP SYN packets per source IP. Since SYN packets are used to initiate connections, a high number of them in a short time is a strong indicator of an attack. I used both real-time memory and CSV logs to improve detection accuracy.

---

## Testing & Screenshots

### Test 1: Normal TCP
Command:
nc -zv 192.168.56.102 80

Screenshot:
- Netcat output
- No alert
![NetCat Output](./screenshots/assignment1_pt1_13)
![No Alert](./screenshots/assignment1_pt1_14)

### Explanation
This test confirms that normal TCP connections are not flagged as attacks. The detector correctly allowed normal traffic.

---

### Test 2: SYN Flood Attack
Command:
sudo hping3 -S -p 80 -i u1000 192.168.56.102

Screenshot:
- Attack running
- Alert triggered
![Attack Running](./screenshots/assignment1_pt1_15)
![Attack Output](./screenshots/assignment1_pt1_16)

### Explanation
This test simulates a SYN flood. The detector identified the abnormal packet rate and generated an alert.

---

### Test 3: Resume Attack
Commands:
sleep 900  
sudo hping3 -S -p 80 -i u1000 192.168.56.102

📸 Screenshot Required:
- Second attack
- Immediate detection
![Attack Running](./screenshots/assignment1_pt1_17)
![Attack Output](./screenshots/assignment1_pt1_18)

### Explanation
This test checks if the detector uses historical data. Since the attack was seen before, it was detected immediately after resuming.

---

### Test 4: IP Spoofing
Command:
sudo hping3 -S -p 80 -i u1000 192.168.56.102

Screenshot:
- Attack running
- Detection behavior
![Attack Running](./screenshots/assignment1_pt1_19)
![Attack Output](./screenshots/assignment1_pt1_20)

### Explanation
This test shows a limitation of the detection system. Because the attacker uses random source IPs, it becomes harder to detect based on per-IP thresholds.

---

# Part 4: Port Scan Detection (25 pts)

## Detection Criteria
- >5 ports/sec  
- >100 ports/min  
- >300 ports/5 min  
- Previous detection in last 30 min  

## Run
python3 port_scanner_detector.py -i eth0  

### Explanation
In this part, I implemented port scan detection using a rate-based approach. The detector tracks how many unique ports a source IP attempts to connect to within a time window. High fan-out rates indicate scanning behavior, which triggers an alert.

---

## Testing & Screenshots

### Test 1: Normal Traffic
Screenshot:
- Normal activity
- No alert
![Activity](./screenshots/assignment1_pt1_21)
![No Alert](./screenshots/assignment1_pt1_22)
### Explanation
This test verifies that regular network activity does not trigger false positives.

---

### Test 2: Nmap Scan
Command:
nmap -p 1-1024 192.168.56.102

Screenshot:
- Nmap output
- Alert triggered
![Nmap Output](./screenshots/assignment1_pt1_23)
![Alert Trigger](./screenshots/assignment1_pt1_24)

### Explanation
This test simulates a standard port scan. The detector correctly identified the scanning behavior based on the number of ports accessed.

---

### Test 3: Fast Scan
Command:
nmap -T4 -p 1-1024 192.168.56.102

Screenshot:
- Fast scan
- Detection output
![Nmap Output](./screenshots/assignment1_pt1_25)
![Alert Trigger](./screenshots/assignment1_pt1_26)

### Explanation
This test shows how the detector handles aggressive scans. The higher speed makes detection easier due to increased fan-out rate.

---

### Test 4: Slow Scan
Command:
nmap -T1 -p 1-1024 192.168.56.102

Screenshot:
- Slow scan
- Detection result
![Nmap Output](./screenshots/assignment1_pt1_27)
Detection Results: No Alerts 

### Explanation
This test evaluates detection against slower scans. Depending on thresholds, slower scans may be harder to detect, which highlights a limitation of rate-based detection.

---



