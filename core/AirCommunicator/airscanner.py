# -*- coding: utf-8 -*-

'''
This module is responsible for scanning the air
for 802.11x packets mostly using the Scapy module
'''

import os
import pyric.pyw as pyw
from AuxiliaryModules.packet import Beacon, ProbeResponse, ProbeRequest, AssociationResponse
from time import sleep
from threading import Thread, Lock
from netaddr import EUI, OUI
from scapy.all import *
from utils.networkmanager import NetworkCard
from utils.utils import DEVNULL
from utils.wifiutils import AccessPoint, WiFiClient, ProbeInfo

class AirScanner(object):

    def __init__(self):
        self.sniffer_running = False
        self.running_interface = None
        self.sniffing_thread = None
        self.sniff_probes = True
        self.sniff_beacons = True

        self.ap_lock, self.client_lock, self.probe_lock = Lock(), Lock(), Lock()
        self.access_points = {}
        self.clients = {}
        self.probes = []

        self.plugins = []

    def is_running(self):
        return self.sniffer_running

    def add_plugin(self, airscanner_plugin):
        self.plugins.append(airscanner_plugin)

    def set_probe_sniffing(self, option):
        self.sniff_probes = option

    def set_beacon_sniffing(self, option):
        self.sniff_beacons = option

    def start_sniffer(self, interface, hop_channels=True, fixed_channel=7):
        self.running_interface = interface
        try:
            card = NetworkCard(interface)
            if card.get_mode().lower() != 'monitor':
                card.set_mode('monitor')
        except:
            print "[-] Could not set card to monitor mode. Card might be busy."
            return

        for plugin in self.plugins:
            plugin.pre_scanning()

        self.sniffer_running = True
        self.sniffing_thread = Thread( target=self.sniff_packets)
        self.sniffing_thread.start()

        if hop_channels:
            hopper_thread = Thread( target=self.hop_channels)
            hopper_thread.start()
        else:
            try:
                card = NetworkCard(interface)
                card.set_channel(fixed_channel)
                if card.get_channel() == fixed_channel:
                    print "[+] Set fixed channel to {}".format(fixed_channel)
                else:
                    print "[-] Could not change channel, try unplugging your interface."
                    print "[/] Channel is on {}".format(card.get_channel())
            except:
                print "[-] Cannot set channel at the moment."

    def stop_sniffer(self):
        Thread(target=self._clean_quit).start()  # Avoids blocking when executed via the console

    def _clean_quit(self, wait = True):
        self.sniffer_running = False
        for plugin in self.plugins:
            plugin.post_scanning()
            plugin.restore()
        del self.plugins[:]

        if wait:
            self.sniffing_thread.join()  # The sniffing_thread will stop once it receives the next packet

        # Reset card operaing state to 'managed'
        if self.running_interface is not None:
            try:
                card = NetworkCard(self.running_interface)
                if card.get_mode().lower() != 'managed':
                    card.set_mode('managed')
            except: pass

        self.running_interface = None

    def sniff_packets(self):
        print "[+] Starting packet sniffer on interface '{}'".format(self.running_interface)

        try:
            conf.use_pcap = True  # Accelerate sniffing -> Less packet loss
            sniff(iface=self.running_interface, store=0, prn=self.handle_packets, stop_filter= (lambda pkt: not self.sniffer_running))
        except Exception as e:
            print str(e)
            print "[-] Exception occurred while sniffing on interface '{}'".format(self.running_interface)

        print "[+] Packet sniffer on interface '{}' has finished".format(self.running_interface)
        self._clean_quit(wait = False)

    def hop_channels(self):
        # Hop through channels to get find more beacons
        try:
            card = NetworkCard(self.running_interface)
            available_channels = card.get_available_channels()
            n_available_channels = len(available_channels)
            current_channel_index = 0
            while self.sniffer_running:
                try:

                    if current_channel_index < n_available_channels:
                        card.set_channel(available_channels[current_channel_index])
                    else:
                        card.set_channel(1)
                        current_channel_index = 0

                    sleep(.25)
                except Exception as e:
                    pass

                current_channel_index += 1
        except Exception as e:
            pass  # The sniffer has already been aborted

    def handle_packets(self, packet):
        # Pass packets through plugins before filtering
        for plugin in self.plugins:
            plugin.handle_packet(packet)

        if self.sniff_beacons:
            if Dot11Beacon in packet:
                self.handle_beacon_packets(packet)

        if self.sniff_probes:
            if Dot11ProbeReq in packet:
                self.handle_probe_req_packets(packet)
            if Dot11ProbeResp in packet:
                self.handle_probe_resp_packets(packet)
            if Dot11AssoResp in packet:
                self.handle_asso_resp_packets(packet)

    def handle_beacon_packets(self, packet):
        beacon = Beacon(packet)
        if beacon.bssid in self.access_points:
            self.access_points[beacon.bssid].rssi = beacon.rssi
            return

        id = len(self.access_points.keys())
        if beacon.ssid is not None:  # Not adding malformed packets
            new_ap = AccessPoint(id, beacon.ssid, beacon.bssid, beacon.channel, beacon.rssi,
                                beacon.encryption, beacon.cipher, beacon.auth)
            with self.ap_lock:
                self.access_points[beacon.bssid] = new_ap

    def handle_probe_req_packets(self, packet):
        probe_req = ProbeRequest(packet)

        if probe_req.client_mac.lower() != "ff:ff:ff:ff:ff:ff":
            probe = self._get_info_from_probe(probe_req, "REQ")
            self._add_probe(probe)
            self._add_client(probe)

    def handle_probe_resp_packets(self, packet):
        probe_resp = ProbeResponse(packet)

        if probe_resp.client_mac.lower() != "ff:ff:ff:ff:ff:ff":
            probe = self._get_info_from_probe(probe_resp, "RESP")
            self._add_probe(probe)
            self._add_client(probe)

    def handle_asso_resp_packets(self, packet):
        asso_resp = AssociationResponse(packet)

        if asso_resp.client_mac.lower() != "ff:ff:ff:ff:ff:ff":
            probe = self._get_info_from_asso(asso_resp, "ASSO")
            self._add_client(probe)

    def _get_info_from_probe(self, probe, probe_type):
        ap_bssids = self.get_bssids_from_ssid(probe.ssid)   # Returns a list with all the bssids
        probe_id = len(self.get_probe_requests())
        probe_info = ProbeInfo(  probe_id, probe.client_mac, probe.client_vendor,
                                 probe.ssid, ap_bssids, probe.rssi, probe_type)
        return probe_info

    def _get_info_from_asso(self, probe, probe_type):
        try:
            probe.ssid = self.access_points[probe.bssid].ssid
        except: pass
        probe_info = ProbeInfo(  0, probe.client_mac, probe.client_vendor,
                                 probe.ssid, [probe.bssid], probe.rssi, probe_type)
        return probe_info

    def _add_probe(self, probeInfo):
        with self.probe_lock:
            try:
                if probeInfo not in self.probes:
                    self.probes.append(probeInfo)
                else:
                    self.probes[self.probes.index(probeInfo)].rssi = probeInfo.rssi             # Just update the rssi
                    self.probes[self.probes.index(probeInfo)].ap_bssids = probeInfo.ap_bssids   # Just update the bssids
            except Exception as e:
                print "Error in airscanner._add_probe"
                print e

    def _add_client(self, probe):
        if probe.ap_ssid == "" and probe.type != "ASSO":
            return

        with self.client_lock:
            client_id = len(self.get_wifi_clients())
            wifiClient = WiFiClient(client_id, probeInfo = probe)
            try:
                if wifiClient not in self.get_wifi_clients():
                    self.clients[probe.client_mac] = wifiClient
                else:
                    wifiClient = self.clients[probe.client_mac]
                    wifiClient.probed_ssids.add(probe.ap_ssid)

                    if probe.type == "ASSO":
                        try:
                            wifiClient.associated_ssid = probe.ap_ssid
                            wifiClient.associated_bssid = probe.ap_bssids[0]
                        except: pass
                    elif probe.type == "REQ":
                        wifiClient.rssi = probe.rssi
            except Exception as e:
                print "Error in airscanner._add_client"
                print e

    def get_access_points(self):
        return [self.access_points[mac]
                for mac in self.access_points.keys()]

    def get_access_point(self, id):
        for ap in self.get_access_points():
            if str(ap.id) == str(id):
                return ap

        return None

    def get_wifi_clients(self):
        return [self.clients[mac]
                for mac in self.clients.keys()]

    def get_probe_requests(self):
        return self.probes

    def get_probe_request(self, id):
        for probe in self.get_probe_requests():
            if str(probe.id) == str(id):
                return probe

        return None

    def get_bssids_from_ssid(self, ssid):
        if not (ssid and ssid != ""):
            return []

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
