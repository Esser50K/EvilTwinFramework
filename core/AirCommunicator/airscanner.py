# -*- coding: utf-8 -*-

'''
This module is responsible for scanning the air 
for 802.11x packets mostly using the Scapy module
'''

import os
import pyric.pyw as pyw
import signal
import traceback
from AuxiliaryModules.packetlogger import PacketLogger
from time import sleep
from threading import Thread, Lock
from netaddr import EUI, OUI
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp
from socket import error as socket_error
from utils.networkmanager import NetworkCard
from utils.utils import DEVNULL


cipher_suites = { 'GROUP'   : '\x00\x0f\xac\x00',
                  'WEP'     : '\x00\x0f\xac\x01',
                  'TKIP'    : '\x00\x0f\xac\x02',
                  'CCMP'    : '\x00\x0f\xac\x04',
                  'WEP'     : '\x00\x0f\xac\x05' }

auth_suites = { 'MGT' : '\x00\x0f\xac\x01',
                'PSK' : '\x00\x0f\xac\x02' }

class AccessPoint(object):
    """
    This class represents an Access Point Object
    Most arguments can be filled out automatically with a scan
    The wpa/wpa2 key has to be specified
    """

    def __init__(self,  id = 0, ssid=None, bssid=None, channel=None, rssi=None,
                        encryption_methods=(), encryption_cipher=None, authentication_method=None):
        self.id = id
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.rssi = rssi
        self.encryption = "/".join(encryption_methods)
        self.cipher = encryption_cipher
        self.auth = authentication_method
        self.psk = None 

    def __str__(self):
        return  " ".join(   [str(self.bssid), str(self.ssid), "/".join(self.encryption), \
                            str(self.cipher), str(self.auth)])

class ProbeInfo(object):

    def __init__(self,  id = 0, 
                        client_mac = None, client_org = None, 
                        ap_ssid = None, ap_bssids = None, 
                        rssi = None, ptype = None):
        self.id = id
        self.client_mac = client_mac
        self.client_org = client_org
        self.ap_bssids = ap_bssids
        self.ap_ssid = ap_ssid
        self.rssi = rssi
        self.type = ptype

    def __eq__(self, other):
        return (self.client_mac == other.client_mac) and (self.ap_ssid == other.ap_ssid)

class AirScanner(object):

    def __init__(self):
        self.sniffer_running = False
        self.running_interface = None
        self.sniffing_thread = None
        self.sniff_probes = True
        self.sniff_beacons = True

        self.ap_lock, self.probe_lock = Lock(), Lock()
        self.access_points = {}
        self.probes = {}

        self.packet_logger = PacketLogger()

    def set_probe_sniffing(self, option):
        self.sniff_probes = option

    def set_beacon_sniffing(self, option):
        self.sniff_beacons = option

    def start_sniffer(self, interface):
        self.running_interface = interface
        card = NetworkCard(interface)
        if card.get_mode() != 'monitor':
            card.set_mode('monitor')
        self.sniffing_thread = Thread( target=self.sniff_packets)
        self.sniffer_running = True
        self.sniffing_thread.start()

        hopper_thread = Thread( target=self.hop_channels)
        hopper_thread.start()

    def stop_sniffer(self):
        Thread(target=self._clean_quit).start() # Avoids blocking when executed via the command line

    def _clean_quit(self, wait = True):
        self.sniffer_running = False
        if wait:
            self.sniffing_thread.join() # The sniffing_thread will stop once it receives the next packet

        # Reset card operaing state to 'managed'
        if self.running_interface != None:
            card = NetworkCard(self.running_interface)
            if card.get_mode() != 'managed':
                card.set_mode('managed')

        self.running_interface = None

    def sniff_packets(self):
        print "[+] Starting packet sniffer on interface '{}'".format(self.running_interface)

        try:
            self.packet_logger.refresh()
            sniff(iface=self.running_interface, store=0, prn=self.handle_packets, stop_filter= (lambda pkt: not self.sniffer_running))
        except socket_error as e:
            if not e.errno == 100:
                print e
                traceback.print_exc()
        except Exception as e:
            print e
            traceback.print_exc()
            print "[-] Exception occurred while sniffing on interface '{}'".format(self.running_interface)

        print "[+] Packet sniffer on interface '{}' has finished".format(self.running_interface)
        self._clean_quit(wait = False)
        
    def hop_channels(self):
        # Hop through channels to get find more beacons
        try:
            card = NetworkCard(self.running_interface)
            while self.sniffer_running:
                current_channel = card.get_channel()
                if current_channel <= 12:
                    card.set_channel(current_channel + 1)
                else:
                    card.set_channel(1)

                sleep(1)
        except Exception as e:
            pass # The sniffer has already been aborted

    def handle_packets(self, packet):
        if self.sniff_beacons and (Dot11Beacon in packet or Dot11ProbeResp in packet):
            self.handle_beacon_packets(packet)
        elif self.sniff_probes and Dot11ProbeReq in packet:
            self.handle_probe_req_packets(packet)

    def handle_beacon_packets(self, packet):
        # Based on an answer from stack-overflow: 
        # https://stackoverflow.com/questions/21613091/how-to-use-scapy-to-determine-wireless-encryption-type

        bssid = packet[Dot11].addr3
        rssi_string = self._get_rssi_from_packet(packet)
        if bssid in self.access_points: # Repetition check
            self.access_points[bssid].rssi = rssi_string
            return

        # Args for AccessPoint object
        encryption = None
        auth_suite = None
        cipher_suite = None
        elt_layer = packet[Dot11Elt]

        cap = packet.sprintf(   "{Dot11Beacon:%Dot11Beacon.cap%}"
                                "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
        rsn_info = None
        ssid, channel = None, None
        crypto = set()
        while isinstance(elt_layer, Dot11Elt):
            if elt_layer.ID == 0:
                ssid = elt_layer.info
            elif elt_layer.ID == 3:
                try:
                    channel = ord(elt_layer.info)
                except Exception:
                    channel = str(elt_layer.info)
            elif elt_layer.ID == 48:
                crypto.add("wpa2")
                rsn_info = elt_layer.info
            elif elt_layer.ID == 221 and elt_layer.info.startswith('\x00P\xf2\x01\x01\x00'):
                crypto.add("wpa")
            elt_layer = elt_layer.payload # Check for more Dot11Elt packets within
        if not crypto:
            if 'privacy' in cap:
                crypto.add("wep")
            else:
                crypto.add("opn")

        if rsn_info or crypto:
            cipher_suite, auth_suite = self.find_auth_and_cipher(rsn_info, crypto)

        id = len(self.access_points.keys())
        new_ap = AccessPoint(id, ssid, bssid, channel, rssi_string, crypto, cipher_suite, auth_suite)
        with self.ap_lock:
            self.access_points[bssid] = new_ap

        if "Dot11ProbeResp" in packet:
            client_mac = packet.addr1
            if client_mac != "":
                maco = EUI(client_mac)                      # EUI - Extended Unique Identifier
                macf = None
                try:
                    macf = maco.oui.registration().org      # OUI - Organizational Unique Identifier
                except Exception as e:
                    pass

                id = len(self.probes.keys())
                probe = ProbeInfo(id, client_mac, macf, ssid, [bssid], rssi_string, "RESP")
                with self.probe_lock:
                    try:
                        if probe not in self.probes[client_mac]:
                            self.probes[client_mac].append(probe)
                    except Exception:
                        self.probes[client_mac] = [probe]


    def handle_probe_req_packets(self, packet): # TODO
        rssi_string = self._get_rssi_from_packet(packet)
        client_mac = packet.addr2 # TODO: Address 1 and 3 are usually broadcast, but could be specific client_mac address
        if packet.haslayer(Dot11Elt):                          
            if packet.ID == 0: 
                ssid = packet.info
                if not ssid or ssid == "":
                    return
                    
                if client_mac != "":
                    maco = EUI(client_mac)                      # EUI - Extended Unique Identifier
                    macf = None
                    try:
                        macf = maco.oui.registration().org      # OUI - Organizational Unique Identifier
                    except Exception as e:                      # OUI not registered exception
                        pass
                    ap_bssid = self.get_bssids_from_ssid(ssid)   # Returns a list with all the bssids

                    id = len(self.probes.keys())
                    probe = ProbeInfo(id, client_mac, macf, ssid, ap_bssid, rssi_string, "REQ")
                    with self.probe_lock:
                        try:
                            if probe not in self.probes[client_mac]:
                                self.probes[client_mac].append(probe)
                        except Exception:
                            self.probes[client_mac] = [probe]


    def _get_rssi_from_packet(self, packet):
        # Found at http://comments.gmane.org/gmane.comp.security.scapy.general/4673
        try:
            return str(-(256-ord(packet.notdecoded[-4:-3]))) + " dbm"
        except Exception:
            return None

                        
    # TODO: Could be better and actually parse the packet instead of searching for byte sequences within
    def find_auth_and_cipher(self, info, crypto_methods):
        cipher_suite = None
        auth_suite = None

        # Figure out cypher suite
        if crypto_methods and info:
            if "wpa2" in crypto_methods and cipher_suites['CCMP'] in info:
                cipher_suite = 'CCMP'
            elif ("wpa" in crypto_methods or "wpa2" in crypto_methods) and cipher_suites['TKIP'] in info:
                cipher_suite = 'TKIP'
            elif "wep" in crypto_methods:
                cipher_suite = 'WEP'

        # Figure out authentication method
        if info:
            if auth_suites['PSK'] in info:
                auth_suite = 'PSK'
            elif auth_suites['MGT'] in info:
                auth_suite = 'MGT'

        return (cipher_suite, auth_suite)

    def get_access_points(self):
        return [self.access_points[mac] 
                for mac in self.access_points.keys()]

    def get_access_point(self, id):
        for ap in self.get_access_points():
            if str(ap.id) == str(id):
                return ap

        return None

    def get_probe_requests(self):
        return [probe 
                for client_mac in self.probes.keys() 
                for probe in self.probes[client_mac]]

    def get_probe_request(self, id):
        for probe in self.get_probe_requests():
            if str(probe.id) == str(id):
                return probe

        return None
        
    def get_bssids_from_ssid(self, ssid):
        if not (ssid and ssid != ""):
            return None

        out = []
        for ap in self.get_access_points():
            if ap.ssid.lower().strip() == ssid.lower().strip():
                out.append(ap.bssid)

        return out

    def get_ssid_from_bssid(self, bssid):
        if not (bssid and bssid != ""):
            return None

        for ap in self.get_access_points():
            if ap.bssid.lower().strip() == bssid.lower().strip():
                return ap.ssid

        return None

    def update_bssids_in_probes(self):
        for probe in self.get_probe_requests():
            if probe.ap_ssid:
                probe.ap_bssids = self.get_bssids_from_ssid(probe.ap_ssid)
