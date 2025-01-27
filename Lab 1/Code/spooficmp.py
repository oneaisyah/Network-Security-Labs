#!/usr/bin/env python3
from scapy.all import *
a = IP()
a.src = '1.2.3.4 '  # Arbitrary spoofed source IP
a.dst = '10.9.0.5'  # Modify to Host A in network to observe in Wireshark
b = ICMP()
p = a / b
send(p)
ls(p)