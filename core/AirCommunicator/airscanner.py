# -*- coding: utf-8 -*-

'''
This module is responsible for scanning the air 
for 802.11x packets mostly using the Scapy module
'''

import os
import pyric.pyw as pyw
import signal
import traceback
from AuxiliaryModules.packet import Beacon, ProbeResponse, ProbeRequest
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
        self.crypto = "/".join(encryption_methods)
        self.cipher = encryption_cipher
        self.auth = authentication_method
        self.psk = None 

    def __str__(self):
        return  " ".join(   [   str(self.bssid), str(self.ssid), \
                                "/".join(self.encryption), \
                                str(self.cipher), str(self.auth)    ]   )

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
        return (self.client_mac == other.client_mac) and (self.ap_ssid == other.ap_ssid) and (self.type == other.type)

    def __str__(self):
        return "{}-{}-{}".format(self.client_mac, self.ap_ssid, self.type)

class AirScanner(object):

    def __init__(self):
        self.sniffer_running = False
        self.running_interface = None
        self.sniffing_thread = None
        self.sniff_probes = True
        self.sniff_beacons = True

        self.ap_lock, self.probe_lock = Lock(), Lock()
        self.access_points = {}
        self.probes = []

        self.plugins = []

    def add_plugin(self, airscanner_plugin):
        self.plugins.append(airscanner_plugin)

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
        Thread(target=self._clean_quit).start() # Avoids blocking when executed via the console

    def _clean_quit(self, wait = True):
        self.sniffer_running = False
        for plugin in self.plugins:
            plugin.restore()
        del self.plugins[:]
        
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
        # Pass packets through plugins before filtering
        for plugin in self.plugins:
            plugin.handle_packet(packet)

        if self.sniff_beacons and Dot11Beacon in packet:
            self.handle_beacon_packets(packet)

        if self.sniff_probes:
            if Dot11ProbeReq in packet:
                self.handle_probe_req_packets(packet)
            if Dot11ProbeResp in packet:
                self.handle_probe_resp_packets(packet)

    def handle_beacon_packets(self, packet):
        # Based on an answer from stack-overflow: 
        # https://stackoverflow.com/questions/21613091/how-to-use-scapy-to-determine-wireless-encryption-type
        beacon = Beacon(packet)
        if beacon.bssid in self.access_points:
            self.access_points[beacon.bssid].rssi = beacon.rssi
            return

        id = len(self.access_points.keys())
        new_ap = AccessPoint(id, beacon.ssid, beacon.bssid, beacon.channel, beacon.rssi, \
                            beacon.encryption, beacon.cipher, beacon.auth)
        with self.ap_lock:
            self.access_points[beacon.bssid] = new_ap

    def handle_probe_req_packets(self, packet): # TODO
        probe_req = ProbeRequest(packet)
        
        if probe_req.client_mac.lower() != "ff:ff:ff:ff:ff:ff":
            probe_req.ap_bssid = self.get_bssids_from_ssid(probe_req.ap_ssid)   # Returns a list with all the bssids
            id = len(self.get_probe_requests())
            probe = ProbeInfo(  id, probe_req.client_mac, probe_req.client_vendor, 
                                probe_req.ssid, probe_req.ap_bssid, probe_req.rssi, "REQ")
            with self.probe_lock:
                try:
                    if probe not in self.probes:
                        self.probes.append(probe)
                    else:
                        self.probes[self.probes.index(probe)].rssi = probe.rssi
                except Exception:
                    pass

    def handle_probe_resp_packets(self, packet):
        probe_resp = ProbeResponse(packet)

        if probe_resp.client_mac.lower() != "ff:ff:ff:ff:ff:ff":
            id = len(self.get_probe_requests())
            probe = ProbeInfo(  id, probe_resp.client_mac, probe_resp.client_vendor, 
                                probe_resp.ssid, [probe_resp.bssid], probe_resp.rssi, "RESP")
            with self.probe_lock:
                try:
                    if probe not in self.probes:
                        self.probes.append(probe)
                    else:
                        self.probes[self.probes.index(probe)].rssi = probe.rssi #Just update the rssi
                except Exception:
                    pass


    def get_access_points(self):
        return [self.access_points[mac] 
                for mac in self.access_points.keys()]

    def get_access_point(self, id):
        for ap in self.get_access_points():
            if str(ap.id) == str(id):
                return ap

        return None

    def get_probe_requests(self):
        return [probe for probe in self.probes]

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
