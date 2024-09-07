ARP Guardian

ARP Guardian is a Python-based tool designed to detect ARP spoofing attacks and provide OS fingerprinting of the attacker. By monitoring ARP packets on the network, ARP Guardian can alert you to potential threats and gather information about the attacker's system.
Features

ARP Spoof Detection: Detects when an ARP cache poisoning attack is occurring by comparing legitimate MAC-IP mappings.
OS Fingerprinting: Performs OS fingerprinting of the attacker based on their response to TCP packets.
Real-time Monitoring: Continuously sniffs the specified network interface for malicious activity.
Command-line Interface: Simple interface to specify the network interface for monitoring.

How It Works

ARP Spoof Detection: ARP Guardian captures ARP responses on your network. If a MAC address does not match the expected one for a given IP, it raises an alert.
OS Fingerprinting: When ARP spoofing is detected, ARP Guardian attempts to fingerprint the attacker's OS by sending a TCP SYN packet and analyzing the TTL and Window size.

Clone the repository:

	git clone https://github.com/dheerajbalan/arpguardian.git
	cd arpgaurdian

Install the required dependencies:

	pip install -r requirements.txt


sudo python arp_guardian.py -i <interface>

Example:

bash

	    sudo python arp_guardian.py -i eth0

Command-line Arguments:
 -i, --interface : Specify the network interface to sniff.

Output

    When the tool is started, it continuously monitors ARP responses on the specified interface.
    If ARP spoofing is detected, it will display the following:
        Attack detected with the attacker's IP and MAC address.
        The legitimate IP and MAC mapping.
        OS fingerprinting results based on TTL and Window size.

Sample output:

python

[+] Starting ARP spoof detection on interface: eth0
[-] You are safe, no one is spoofing your ARP
[!] ARP spoofing detected...
Spoofing detected from IP 192.168.1.105 with MAC aa:bb:cc:dd:ee:ff
Attacker's real IP: 192.168.1.105
Attacker's real MAC: 11:22:33:44:55:66
OS Detected: Linux system (TTL: 64, Window: 29200)

System Requirements

    Python 3.x
    Scapy
    Colorama

Disclaimer

ARP Guardian is an educational tool intended for use on networks where you have permission to monitor. Unauthorized monitoring or network sniffing is illegal and unethical.
Contributing

Feel free to contribute by creating issues, improving documentation, or adding features! Pull requests are welcome.
