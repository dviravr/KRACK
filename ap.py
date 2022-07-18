import os
import sys
import time

from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap
from scapy.sendrecv import sniff, sendp
from scapy.volatile import RandMAC

iface_client = 'wlp2s0'
iface_ap = 'wlxc4e9841e1a74'
client_mac = 'c4:9a:02:57:30:23'
ap_mac = 'd4:35:1d:6c:e2:34'
ap_ssid = 'Avrahami'


def print_green(string: str):
    print(f'\033[92m{string}\033[00m')


def print_red(string: str):
    print(f'\033[31m{string}\033[00m')


def print_blue(string: str):
    print(f'\033[34m{string}\033[00m')


def set_ap():
    def stop_attack():
        os.system('service hostapd stop')
        os.system('service dnsmasq stop')
        os.system('killall dnsmasq')
        os.system('killall hostapd')
        os.system('systemctl start NetworkManager')

    def enable_nat():
        os.system('bash enable-nat.sh')

    def set_ip():
        os.system(f'ip addr add 10.0.0.1/24 dev {iface_ap}')

    def set_monitor_mode(iface: str):
        os.system(f'ifconfig {iface_ap} down')
        print_blue(f'starting monitor mode for {iface}')
        try:
            os.system(f'iwconfig {iface} mode monitor')
        except Exception:
            print_red('could not start monitor mode')
            sys.exit()
        print_green(f'interface {iface} is on monitor mode')
        os.system(f'ifconfig {iface_ap} up')

    def start_ap():
        print_blue('activate dnsmasq...')
        os.system('dnsmasq -C ./dnsmasq.conf')

        print_blue('activate hostapd...')
        os.system('hostapd ./hostapd.conf')

    set_monitor_mode(iface_ap)
    set_ip()
    enable_nat()
    stop_attack()
    start_ap()


if __name__ == '__main__':
    set_ap()
