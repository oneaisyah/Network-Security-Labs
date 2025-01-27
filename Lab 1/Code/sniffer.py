#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

# Capture only the ICMP packet
#pkt = sniff(iface='br-4ab028389181', filter='icmp', prn=print_pkt)

# Capture any TCP packet that comes from a particular IP and with a destination port number 23
#pkt = sniff(iface='br-4ab028389181', filter='tcp && src host 10.9.0.5 && dst port 23', prn=print_pkt)

# Capture packets comes from or to go to a particular subnet. You can pick any subnet, such as 128.230.0.0/16; you should not pick the subnet that your VM is attached to
#pkt = sniff(iface='br-4ab028389181', filter='net 128.230.0.0/16', prn=print_pkt)
