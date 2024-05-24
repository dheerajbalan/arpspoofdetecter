#!/usr/bin/python3
import scapy.all as scapy
import argparse
from colorama import Fore

green = Fore.GREEN
red = Fore.RED

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
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

safe_printed = False

def sniff(interface):
    try:
        scapy.sniff(iface=interface, store=False, prn=detect_arp_spoof)
    except Exception as e:
        print("An error occurred while sniffing: ", e)

def detect_arp_spoof(packet):
    global safe_printed
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print(red + "[!] You are under attack!!!")
                safe_printed = False
            elif not safe_printed:
                print(green + "[-] You are safe, no one is spoofing your ARP")
                safe_printed = True
        except IndexError:
            pass

# Print colorful banner
get_banner()

# Parse command-line arguments
args = get_arguments()

# Start sniffing
if args.interface:
    print(green + "[+] Starting ARP spoof detection on interface: " + args.interface)
    sniff(args.interface)
else:
    print(red + "[-] Please specify a network interface using the -i option.")
