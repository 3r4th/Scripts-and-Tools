#!/usr/bin/env python

__author__ = "3r4th"

import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-n", "--new-mac", dest="new_mac", help="Set a new MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    elif not options.new_mac:
        parser.error("[-] Please specify a new mac address, use --help for more info")
    return options


def get_current_mac(interface):
    try:
        ifconfig_result = subprocess.check_output(["ifconfig", interface])
    except subprocess.CalledProcessError as exception:
        print(exception.output)
        exit(1)
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    print("[-] Could not read MAC address for the given interface")
    exit(0)


def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


if __name__ == "__main__":
    options = get_arguments()
    current_mac = get_current_mac(options.interface)
    print("Current MAC : " + str(current_mac))
    change_mac(options.interface, options.new_mac)
    current_mac = get_current_mac(options.interface)
    if current_mac == options.new_mac:
        print("[+] MAC address was successfully changed to " + current_mac)
        print("[!] To reset the MAC address to its original (permanent hardware value), type the commands below :")
        print(" >  ifconfig " + options.interface + " down")
        print(" >  ifconfig " + options.interface + " hw ether $(ethtool -P " + options.interface + " | awk '{print $3}')")
        print(" >  ifconfig " + options.interface + " up")
    else:
        print("[-] MAC address did not get changed")
