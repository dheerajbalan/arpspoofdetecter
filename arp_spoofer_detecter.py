#!/usr/bin/python3
from scapy.all import sniff, ARP, Ether, srp, IP, TCP, sr1  # Import specific functions
import argparse
from colorama import Fore

green = Fore.GREEN
red = Fore.RED
blue = Fore.BLUE
yellow = Fore.YELLOW
cyan = Fore.CYAN

def get_banner():
    banner = """
                                                              
   _____  _____  _____  _____                   _  _           
  |  _  || __  ||  _  ||   __| ___  _ _  ___  _| ||_| ___  ___ 
  |     ||    -||   __||  |  || .'|| | ||  _|| . || || .'||   |
  |__|__||__|__||__|   |_____||__,||___||_|  |___||_||__,||_|_|
                                                               
    """
    print(red + banner)

def get_arguments():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--interface", dest="interface", help="Specify the network interface to sniff")
    return parse.parse_args()

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

safe_printed = False
legitimate_ip = {}

def sniff_packets(interface):
    try:
        sniff(iface=interface, store=False, prn=detect_arp_spoof)
    except Exception as e:
        print("An error occurred while sniffing: ", e)

def detect_arp_spoof(packet):
    global safe_printed
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        source_ip = packet[ARP].psrc
        source_mac = packet[ARP].hwsrc
        
        if source_ip in legitimate_ip:
            if legitimate_ip[source_ip] != source_mac:
                print(red + "[!] ARP spoofing detected...")
                print(yellow + f"Spoofing detected from IP {source_ip} with MAC {source_mac}")
                print(cyan + f"Attacker's real IP: {source_ip}")
                print(cyan  + f"Attacker's real MAC: {legitimate_ip[source_ip]}")
                get_os(source_ip)
                safe_printed = False
            elif not safe_printed:
                print(blue + "[-] You are safe, no one is spoofing your ARP")
                safe_printed = True
        else:
            legitimate_ip[source_ip] = source_mac
            print(green + f"Learned new mapping {source_ip} --> {source_mac}")

def get_os(source_ip):
    try:
        resp = sr1(IP(dst=source_ip)/TCP(dport=80, flags="S"), timeout=1, verbose=False)
        
        if resp:
            ttl = resp[IP].ttl
            window = resp[TCP].window
            
            if ttl <= 64 and window <= 65535:
                print(green + f"OS Detected: Linux system (TTL: {ttl}, Window: {window})")
            elif ttl <= 128 and window > 65535:
                print(green + f"OS Detected: Windows system (TTL: {ttl}, Window: {window})")
            else:
                print(red + "Unknown OS detected.")
        else:
            print(red + "Could not find OS information.")
    except Exception as e:
        print(red + f"Error while detecting OS: {e}")

# Print colorful banner
get_banner()

# Parse command-line arguments
args = get_arguments()

# Start sniffing
if args.interface:
    print(green + "[+] Starting ARP spoof detection on interface: " + args.interface)
    sniff_packets(args.interface)
else:
    print(red + "[-] Please specify a network interface using the -i option.")
