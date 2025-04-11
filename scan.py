#!/usr/bin/env python3

import scapy.all as scapy
from mac_vendor_lookup import MacLookup
from optparse import OptionParser


# Function to handle command-line arguments
def get_arguments():
    parser = OptionParser()
    parser.add_option("-i", "--ip", dest="ip", help="IP address or network to scan")
    (options, args) = parser.parse_args()

    if not options.ip:
        parser.error("[-] Please specify an IP address or range using -i option.")
    return options


# Function to scan the network and collect client details
def scan_network(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients = []
    for response in answered_list:
        mac = response[1].hwsrc
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = "Unknown"

        client_info = {"IP": response[1].psrc, "MAC": mac, "VENDOR": vendor}
        clients.append(client_info)

    return clients


# Function to print the scan results in a table format
def display_results(clients):
    print("\nIP Address\t\tMAC Address\t\t\tVendor")
    print("--------------------------------------------------------------")
    for client in clients:
        print(f"{client['IP']}\t\t{client['MAC']}\t{client['VENDOR']}")


# Main Execution
if __name__ == "__main__":
    options = get_arguments()
    scan_results = scan_network(options.ip)
    display_results(scan_results)
