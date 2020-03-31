#!/usr/bin/env python

__author__ = "3r4th"

import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--range", dest="range", help="IP range to scan")
    option = parser.parse_args()[0]
    if not option.range:
        parser.error("[-] Please specify an IP range to scan, use --help for more info")
    return option


def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    (answered_list, unanswered_list) = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_result(results_list):
    if len(results_list):
        print("IP" + "\t" * 2 + "MAC Address \n" + "-" * 35)
        for client in results_list:
            print(client["ip"] + "\t" + client["mac"])
    else:
        print("[!] No connected machine detected, check your IP range")


if __name__ == "__main__":
    option = get_arguments()
    scan_result = scan_network(option.range)
    print_result(scan_result)
