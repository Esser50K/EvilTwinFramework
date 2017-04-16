"""
This plugin attempts to read and log certificate information of
EAP enabled WiFi networks

This is based on the EAPeak project
"""
import os
from pyric import pyw as pyw
from plugin import AirScannerPlugin
from AuxiliaryModules.packet import Beacon
from scapy.all import Ether, Dot11Beacon, EAPOL, EAP, LEAP, PcapWriter, sniff, load_contrib
from utils.networkmanager import NetworkCard
from utils.utils import NetUtils
from threading import Thread
from time import sleep
try:  # Python Scapy-Com check (inspiration from EAPEAK/McIntyre)
	from scapy.layers.l2 import eap_types as EAP_TYPES
except ImportError:
	print "[-] Community version of Scapy (Scapy-Com) is missing, please run setup.py for full instalation"


class EAPCertLogger(AirScannerPlugin):

	def __init__(self):
		super(CredentialSniffer, self).__init__("eapcertlogger")
		self.known_network_bssids = set()

		self.fragment_buffer = {}

	def handle_packet(self, packet):
		if packet.name == 'RadioTap dummy':
			packet = packet.payload  # Offset it so we start with the Dot11 header

		if Dot11Beacon in packet:
			packet = Beacon(packet)
			self.known_network_bssids.add(packet.bssid)
			return

		shouldStop = False

		if not Dot11 in packet:
			return

		mac = packet[Dot11].addr3
		if mac.lower() == "ff:ff:ff:ff:ff:ff":
			mac = packet[Dot11].addr2

		if not mac in self.known_network_bssids:
			return

		# This section extracts useful EAP info
		cert_layer = None
		if 'EAP' in packet:
			fields = packet.getlayer('EAP').fields
			if fields['code'] not in [1, 2]:
				return
			eaptype = fields['type']

			network.addEapType(eaptype)

			if eaptype == 254 and packet.haslayer('EAP_Expanded'):
				network.add_expanded_vendor_id(packet.getlayer('EAP_Expanded').vendor_id)
			if packet.haslayer('LEAP'):
				self.get_leap_from_ap_data(packet, client)
			elif packet.getlayer(EAP).payload.name in ['EAP_TLS', 'EAP_TTLS', 'PEAP', 'EAP_Fast']:
				cert_layer = self.get_eap_data(packet, bssid, client_mac)

			if not cert_layer:
				shouldStop = True

		if shouldStop:
			return

		if cert_layer and 'certificate' in cert_layer.fields:
			self.get_cert_data(network, cert_layer)


