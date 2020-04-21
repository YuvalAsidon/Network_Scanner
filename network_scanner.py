#!/usr/bin/env python3
import argparse
from scapy.all import *


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Targets IP address or IP range")
    return parser.parse_args()


def scan(ip):
    # set the IP for the ARP request
    arp_request = scapy.all.ARP(pdst=ip)
    # set the MAC address to the broadcast MAC address the point of using Ether is to make sure that the packet that
    # we'll be sending will be sent to the broadcast address and not to only one device
    broadcast = scapy.all.Ether(dst='ff:ff:ff:ff:ff:ff')
    # append the 2 packet to 1
    arp_request_broadcast = broadcast / arp_request
    ans_list = scapy.all.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    client = []
    for answer in ans_list:
        client.append({"ip": answer[1].psrc, "mac": answer[1].hwsrc})
    return client


def print_client(client):
    print("IP\t\t\tAt MAC Address")
    print("---------------------------------------------------------")
    for cl in client:
        print(cl["ip"] + "\t\t" + cl["mac"])
        print("---------------------------------------------------------")


print_client(scan(get_arguments().target))
