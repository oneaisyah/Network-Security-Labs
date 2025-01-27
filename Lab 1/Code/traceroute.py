#!/usr/bin/env python3
from scapy.all import *
import argparse

def traceroute(dst, max_hops=30):
	for ttl in range(1, max_hops + 1):
		a = IP()
		a.dst = dst
		a.ttl = ttl
		b = ICMP()
		reply = sr1(a/b, timeout=5)
		
		if reply is None:
			print(f"TTL={ttl}: No response")
			continue
		if reply.type == 11: # TTL exceeded
			print(f"TTL={ttl}: {reply.src}")
		elif reply.type == 0: # Echo reply
			print(f"{reply.src} reached! TTL={ttl}")
			break

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("host", type=str)
	args = parser.parse_args()
	
	traceroute(args.host)