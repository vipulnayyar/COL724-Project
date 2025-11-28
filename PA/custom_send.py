#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Reason-GPL: import-scapy
import random
import socket
import sys
import csv

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    if len(sys.argv)<2:
        print('pass 2 arguments: <destination>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))
    
    with open('aggregated_flow_stats.csv', 'r') as f:
        source_ports = {}
        source_port_count = 49152

        reader = csv.reader(f)
        for row in reader:
            ip_pair = (row[0], row[1])
            if ip_pair in source_ports:
                source_port = source_ports[ip_pair]
            else:
                source_ports[ip_pair] = source_port_count
                source_port = source_port_count
                source_port_count += 1
            
            print(f"Sending {int(row[2])} packets from {source_port} to {addr}")
            #for _ in range(int(row[2])): 
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=source_port) / "HELLO"
            #pkt.show2()
            sendp(pkt, iface=iface, verbose=False, count=(int(row[2])))


if __name__ == '__main__':
    main()

