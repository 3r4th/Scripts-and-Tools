# Scripts-and-Tools
Scripts and tools written in python for ethical hacking.

### Note :
Scripts below use optparse, this module is deprecated, still working on Python 3 and replaced by **argparse**.

### mac_changer.py
Script to change the MAC address on linux.

#### Use
Python 2 or 3

#### Example
```Bash
python mac_changer.py -i <interface> -n <new_mac_address>
```
### network_scanner.py
Script to scan for connected devices

#### Use
Python 2 or 3

#### Example
```Bash
python network_scanner.py -r <ip_range>
```
### arp_spoofer_v2.py
Script that allows you to perform ARP spoofing written in Python 2

#### Use
Python 2

#### Example
```Bash
python arp_spoofer_v2.py -g <gatway_ip> -v <victim_ip>
```
### arp_spoofer_v3.py
Script that allows you to perform ARP spoofing written in Python 3

#### Use
Python 3

#### Example
```Bash
python3 arp_spoofer_v3.py -g <gatway_ip> -v <victim_ip>
```
### packet_sniffer.py
Script to sniff and analyze data. You can use it with arp_spoofer to perform a MITM attack.

#### Use
Python 2 or 3

#### Example
```Bash
python packet_sniffer.py -i <interface>
```

