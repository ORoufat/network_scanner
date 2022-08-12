#!/usr/bin/venv/ python

import scapy.all as scapy

'''Sending ARP requests to network 192.168.98.1/24 over Ethernet Interface to the destination ip of Layer 2 
Broadcast '''

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    '''Using srp to send packets with a custom Ether layer and receive a response'''
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    '''Displaying the MAC Addresses of the clients'''
    client_list =[]
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


scan_result = scan("192.168.98.1/24")
print_result(scan_result)



