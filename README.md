# Scripts-and-Tools
Scripts and tools written in python for ethical hacking.

### > Note :
Scripts below use **optparse**, this module is deprecated, still working on Python 3 and replaced by **argparse**.

Use **pip** or **pip3** to install required packages.
___
### > mac_changer.py
Script to change the MAC address on linux.

#### Use
Python 2 or 3

#### Example
```Bash
python mac_changer.py -i <interface> -n <new_mac_address>
```
___
### > network_scanner.py
Script to scan for connected devices

#### Use
Python 2 or 3

#### Example
```Bash
python network_scanner.py -r <ip_range>
```
___
### > arp_spoofer_v2.py
Script that allows you to perform ARP spoofing written in Python 2

#### Use
Python 2

#### Example
```Bash
python arp_spoofer_v2.py -g <gatway_ip> -v <victim_ip>
```
___
### > arp_spoofer_v3.py
Script that allows you to perform ARP spoofing written in Python 3

#### Use
Python 3

#### Example
```Bash
python3 arp_spoofer_v3.py -g <gatway_ip> -v <victim_ip>
```
___
### > packet_sniffer.py
Script to sniff and analyze data. You can use it with arp_spoofer to perform a MITM attack.

#### Use
Python 2 or 3

#### Example
##### Open a terminal a run : 
```Bash
python arp_spoofer_v2.py -g <gatway_ip> -v <victim_ip>
```
##### In another terminal, run : 
```Bash
python packet_sniffer.py -i <interface>
```
___
### dns_spoofer.py
Script that allows you to perform DNS spoofing after being a MITM using for example my arp_spoofer script.

#### Use
Python 2 or 3

#### Example
##### Open a terminal a run : 
```Bash
python arp_spoofer_v2.py -g <gatway_ip> -v <victim_ip>
```
##### In another terminal, run : 
```Bash
python dns_spoofer.py -d <domain_name> -i <ip_address>
```
___
### file_interceptor.py
The script will intercept any file corresponding to the extension you specified and will replace it with your evil file after being a MITM using for example my arp_spoofer script.

#### Use
Python 2 or 3
#### Example
##### Open a terminal a run : 
```Bash
python arp_spoofer_v2.py -g <gatway_ip> -v <victim_ip>
```
##### In another terminal, run : 
```Bash
python file_interceptor -e <extension> -f <link_to_your_evil_file>
```
___
### code_injector.py
The script will inject the code (JavaScript, html, etc ...) that you want. Just put it in the variable "injection_code" in the script. Note that you can combine it with Beef framework.

#### Use
Python 2 or 3
#### Example
##### Open a terminal a run : 
```Bash
python arp_spoofer_v2.py -g <gatway_ip> -v <victim_ip>
```
##### In another terminal, run : 
```Bash
python code_injector
```
