#!/bin/bash

VM_D="192.168.56.103"
VM_T="192.168.56.101"
INTERNAL_NET="192.168.56.0/24"
IFACE="eth0"

iptables -F
iptables -X
iptables -Z

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "MALFORMED INVALID: "
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j LOG --log-prefix "MALFORMED LOOPBACK: "
iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j DROP

iptables -A INPUT -s "$VM_D" -j LOG --log-prefix "MALFORMED SELF-SRC: "
iptables -A INPUT -s "$VM_D" -j DROP

iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "SCAN-TCP NULL: "
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j LOG --log-prefix "SCAN-TCP XMAS: "
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG --log-prefix "SCAN-TCP SYN-FIN: "
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

iptables -A INPUT -s "$INTERNAL_NET" -p icmp --icmp-type echo-request -m limit --limit 5/second --limit-burst 10 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-prefix "DOS-RATE-LIMIT ICMP: "
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

iptables -A INPUT -s "$INTERNAL_NET" -p tcp --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 32 -j LOG --log-prefix "DOS-RATE-LIMIT HTTP-CONN: "
iptables -A INPUT -s "$INTERNAL_NET" -p tcp --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP

iptables -A INPUT -s "$INTERNAL_NET" -p tcp --dport 80 -m state --state NEW -m limit --limit 10/second --limit-burst 20 -j ACCEPT
iptables -A INPUT -s "$INTERNAL_NET" -p tcp --dport 80 -j LOG --log-prefix "DOS-RATE-LIMIT HTTP: "
iptables -A INPUT -s "$INTERNAL_NET" -p tcp --dport 80 -j DROP

iptables -A INPUT -s "$VM_T" -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
iptables -A INPUT -s "$VM_T" -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j LOG --log-prefix "DOS-RATE-LIMIT SSH: "
iptables -A INPUT -s "$VM_T" -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -s "$VM_T" -p tcp --dport 22 -j ACCEPT

iptables -A INPUT ! -s "$INTERNAL_NET" -j LOG --log-prefix "ILLEGAL-IP/PORT EXT: "
iptables -A INPUT ! -s "$INTERNAL_NET" -j DROP

iptables -A INPUT -p tcp --syn -m limit --limit 5/second --limit-burst 10 -j ACCEPT
iptables -A INPUT -p tcp --syn -j LOG --log-prefix "DOS-RATE-LIMIT SYN: "
iptables -A INPUT -p tcp --syn -j DROP

iptables -A INPUT -p tcp --dport 22 -j LOG --log-prefix "ILLEGAL-IP/PORT SSH: "
iptables -A INPUT -p tcp --dport 22 -j DROP

iptables -A INPUT -j LOG --log-prefix "DROP-GENERIC: "
iptables -A INPUT -j DROP