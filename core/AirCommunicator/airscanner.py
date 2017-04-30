# -*- coding: utf-8 -*-

'''
This module is responsible for scanning the air 
for 802.11x packets mostly using the Scapy module
'''

import os
import pyric.pyw as pyw
import traceback
from AuxiliaryModules.packet import Beacon, ProbeResponse, ProbeRequest
from time import sleep
from threading import Thread, Lock
from netaddr import EUI, OUI
#from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, EAPOL, EAP
from scapy.all import *
from utils.networkmanager import NetworkCard
from utils.utils import DEVNULL

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

class WiFiClient(object):
	"""
	This class represents a WiFi Client
	These are detected whenever they send probe send probe requests
	One can check if they are associated if the Access Point has responded
	"""

	def __init__(self, id = 0, probeInfo = None):
		self.id = id
		self.client_mac = None
		self.client_org = None
		self.probed_ssids = None
		self.rssi = None
		self.associated_ssid = None
		self._parse_probe(probeInfo)

	def is_associated(self):
		return self.associated_ssid != None

	def _parse_probe(self, probeInfo):
		if probeInfo != None:
			self.client_mac = probeInfo.client_mac
			self.client_org = probeInfo.client_org
			self.probed_ssids = set([probeInfo.ap_ssid])
			if probeInfo.type == "REQ":
				self.rssi = probeInfo.rssi

	def __eq__(self, other):
		return self.client_mac == other.client_mac


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

	def isPair(self, otherProbe):
		return 	(self.client_mac == other.client_mac) and \
				(self.ap_ssid == other.ap_ssid) and \
				(self.type != other.type)

	def __eq__(self, other):
		return 	(self.client_mac == other.client_mac) and \
				(self.ap_ssid == other.ap_ssid) and \
				(self.type == other.type)

	def __str__(self):
		return "{}-{}-{}".format(self.client_mac, self.ap_ssid, self.type)

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

	def add_plugin(self, airscanner_plugin):
		self.plugins.append(airscanner_plugin)

	def set_probe_sniffing(self, option):
		self.sniff_probes = option

	def set_beacon_sniffing(self, option):
		self.sniff_beacons = option

	def start_sniffer(self, interface, hop_channels=True, fixed_channel=7):
		self.running_interface = interface
		card = NetworkCard(interface)
		if card.get_mode() != 'monitor':
			card.set_mode('monitor')

		for plugin in self.plugins:
			plugin.pre_scanning()

		self.sniffer_running = True
		self.sniffing_thread = Thread( target=self.sniff_packets)
		self.sniffing_thread.start()

		if hop_channels:
			hopper_thread = Thread( target=self.hop_channels)
			hopper_thread.start()
		else:
			card = NetworkCard(interface)
			card.set_channel(fixed_channel)

	def stop_sniffer(self):
		Thread(target=self._clean_quit).start() # Avoids blocking when executed via the console

	def _clean_quit(self, wait = True):
		self.sniffer_running = False
		for plugin in self.plugins:
			plugin.post_scanning()
			plugin.restore()
		del self.plugins[:]
		
		if wait:
			self.sniffing_thread.join() # The sniffing_thread will stop once it receives the next packet

		# Reset card operaing state to 'managed'
		if self.running_interface != None:
			try:
				card = NetworkCard(self.running_interface)
				if card.get_mode() != 'managed':
					card.set_mode('managed')
			except: pass

		self.running_interface = None

	def sniff_packets(self):
		print "[+] Starting packet sniffer on interface '{}'".format(self.running_interface)

		try:
			sniff(iface=self.running_interface, store=0, prn=self.handle_packets, stop_filter= (lambda pkt: not self.sniffer_running))
		except Exception as e:
			print e
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
			pass # The sniffer has already been aborted

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


	def handle_beacon_packets(self, packet):
		beacon = Beacon(packet)
		if beacon.bssid in self.access_points:
			self.access_points[beacon.bssid].rssi = beacon.rssi
			return

		id = len(self.access_points.keys())
		if beacon.ssid != None: #Not adding malformed packets
			new_ap = AccessPoint(id, beacon.ssid, beacon.bssid, beacon.channel, beacon.rssi, \
								beacon.encryption, beacon.cipher, beacon.auth)
			with self.ap_lock:
				self.access_points[beacon.bssid] = new_ap

	def handle_probe_req_packets(self, packet):
		probe_req = ProbeRequest(packet)
		
		if probe_req.client_mac.lower() != "ff:ff:ff:ff:ff:ff":
			probe = self._get_probe_info_from_probe(probe_req, "REQ")
			self._add_probe(probe)
			self._add_client(probe)
			

	def handle_probe_resp_packets(self, packet):
		probe_resp = ProbeResponse(packet)

		if probe_resp.client_mac.lower() != "ff:ff:ff:ff:ff:ff":
			probe = self._get_probe_info_from_probe(probe_resp, "RESP")
			self._add_probe(probe)
			self._add_client(probe)

	def _get_probe_info_from_probe(self, probe, probe_type):
		probe.ap_bssids = self.get_bssids_from_ssid(probe.ssid)   # Returns a list with all the bssids
		probe_id = len(self.get_probe_requests())
		probe = ProbeInfo(  probe_id, probe.client_mac, probe.client_vendor, 
							probe.ssid, probe.ap_bssids, probe.rssi, probe_type)
		return probe

	def _add_probe(self, probeInfo):
		with self.probe_lock:
			try:
				if probeInfo not in self.probes:
					self.probes.append(probeInfo)
				else:
					self.probes[self.probes.index(probeInfo)].rssi = probeInfo.rssi 			#Just update the rssi
					self.probes[self.probes.index(probeInfo)].ap_bssids = probeInfo.ap_bssids 	#Just update the bssids
			except Exception as e:
				print "Error in airscanner._add_probe"
				print e
				pass

	def _add_client(self, probe):
		if probe.ap_ssid == "":
			return
			
		with self.client_lock:
			client_id = len(self.get_wifi_clients())
			wifiClient = WiFiClient(client_id, probe)
			try:
				if wifiClient not in self.get_wifi_clients():
					self.clients[probe.client_mac] = wifiClient
				else:
					wifiClient = self.clients[probe.client_mac]
					wifiClient.probed_ssids.add(probe.ap_ssid)

					if probe.type == "RESP":
						wifiClient.associated_ssid = probe.ap_ssid
					else:
						wifiClient.rssi = probe.rssi
			except Exception as e:
				print "Error in airscanner._add_client"
				print e
				pass


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