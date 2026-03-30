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

### Explanation
I set up three virtual machines on the same local network to simulate a real attack environment. The defense machine was used to run my detection tools, while the attack machine generated traffic such as scans and floods. The target machine acted as the victim. Promiscuous mode was important because it allowed the sniffer to capture all packets on the network, not just those addressed to it.

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
![Promiscuous Mode + Sniffer Running](./screenshots/assignment1_pt1ts1) 

### Explanation
For this part, I extended my packet sniffer to capture all IPv4 traffic and log important fields like source IP, destination IP, and protocol type. I used a deque to store only the last 10 minutes of traffic so the system would not run out of memory. I also implemented batch writing to a CSV file to make logging more efficient and avoid excessive disk writes.

---

## Testing & Screenshots

### Test 1: ICMP Ping
Command:
ping 192.168.56.102 

Screenshot:
- Ping command running
- Sniffer output showing ICMP packets
![ICMP Packets](./screenshots/assignment1_pt1ts2) 

### Explanation
This test verifies that the sniffer correctly captures ICMP packets. I used a simple ping command and confirmed that the packets appeared in the logs.

---

### Test 2: Port Scan
Command:
nmap -Pn -sS -p 22,80,443 192.168.56.102

Screenshot:
- Nmap output
- Sniffer logs showing SYN packets
![Nmap](./screenshots/assignment1_pt1ts3) 

### Explanation
This test checks if the sniffer detects SYN packets from a port scan. I used Nmap to scan a few ports and confirmed that each SYN request was captured.

---

### Test 3: SYN Flood
Command:
sudo hping3 -S -p 80 -i u1000 192.168.56.102

Screenshot:
- Sniffer showing high SYN traffic
![SYN Flood](./screenshots/assignment1_pt1ts4) 

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

### Explanation
In this part, I built a detector that monitors ICMP traffic and identifies flooding behavior based on packet rate. The detector tracks how many ICMP requests each IP sends per second and triggers an alert if it exceeds the threshold for a sustained period. I also added a check using the CSV logs to identify repeat attackers.

---

## Testing & Screenshots

### Test 1: Normal Traffic
Command:
ping -c 5 <MS2-IP>  

📸 Screenshot Required:
- Ping output
- No alert from detector

### Explanation
This test ensures that normal ICMP traffic does not trigger false positives. The detector correctly ignored regular ping activity.

---

### Test 2: ICMP Flood Attack
Command:
hping3 -1 -flood -d 120 -a 192.168.10.50 <MS2-IP>  

📸 Screenshot Required:
- Attack command
- Detector alert output

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
nc -zv <MS2-IP> 80  

📸 Screenshot Required:
- Netcat output
- No alert

### Explanation
This test confirms that normal TCP connections are not flagged as attacks. The detector correctly allowed normal traffic.

---

### Test 2: SYN Flood Attack
Command:
hping3 -S -p 80 -i u1000 <MS2-IP>  

📸 Screenshot Required:
- Attack running
- Alert triggered

### Explanation
This test simulates a SYN flood. The detector identified the abnormal packet rate and generated an alert.

---

### Test 3: Resume Attack
Commands:
sleep 900  
hping3 -S -p 80 -i u1000 <MS2-IP>  

📸 Screenshot Required:
- Second attack
- Immediate detection

### Explanation
This test checks if the detector uses historical data. Since the attack was seen before, it was detected immediately after resuming.

---

### Test 4: IP Spoofing
Command:
hping3 -S -p 80 -i u1000 --rand-source <MS2-IP>  

📸 Screenshot Required:
- Attack running
- Detection behavior

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
📸 Screenshot Required:
- Normal activity
- No alert

### Explanation
This test verifies that regular network activity does not trigger false positives.

---

### Test 2: Nmap Scan
Command:
nmap <MS2-IP>  

📸 Screenshot Required:
- Nmap output
- Alert triggered

### Explanation
This test simulates a standard port scan. The detector correctly identified the scanning behavior based on the number of ports accessed.

---

### Test 3: Fast Scan
Command:
nmap -T4 <MS2-IP>  

📸 Screenshot Required:
- Fast scan
- Detection output

### Explanation
This test shows how the detector handles aggressive scans. The higher speed makes detection easier due to increased fan-out rate.

---

### Test 4: Slow Scan
Command:
nmap -T1 <MS2-IP>  

📸 Screenshot Required:
- Slow scan
- Detection result

### Explanation
This test evaluates detection against slower scans. Depending on thresholds, slower scans may be harder to detect, which highlights a limitation of rate-based detection.

---

# Submission Requirements

## Code
- packet_sniffer.py  
- icmp_flood_detector.py  
- syn_flood_detector.py  
- port_scanner_detector.py  

## Report Includes
- Implementation  
- Testing  
- Screenshots  
- Analysis  
- Improvements  

---

# Grading Rubric

| Component | Points |
|----------|--------|
| Packet Sniffer | 10 |
| ICMP Detection | 15 |
| SYN Detection | 20 |
| Port Scan Detection | 25 |
| Documentation | 30 |
| **Total** | **100** |


