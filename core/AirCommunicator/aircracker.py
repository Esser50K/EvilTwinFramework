import sys, os
from netaddr import EUI, OUI


class WPAHandshake(object):
	"""
	Minimalistic representation of a WPA handshake
	Info is parsed from the file names and is enough to pass arguments
	to coWPAtty and HalfWPACracker
	"""
	def __init__(self, id=0, ssid=None, client_mac=None, location = None):
		self.id = id
		self.ssid = ssid
		self.client_mac = client_mac
		self.client_org = None
		try:
			self.client_org = EUI(self.client_mac).oui.registration().org  	# OUI - Organizational Unique Identifier
		except: pass														# OUI not registered exception
		self.location = location



class AirCracker(object):

	def __init__(self, wpa_cracker = None):
		self.wpa_handshakes 		= []
		self.half_wpa_handshakes 	= []
		self.wpa_cracker = wpa_cracker
		self.load_wpa_handshakes()
		self.load_half_wpa_handshakes()

	def load_wpa_handshakes(self):
		del self.wpa_handshakes[:]
		for handshake in os.listdir("data/wpa_handshakes"):
			handshake = self._parse_filename_to_handshake(handshake, False)
			if handshake != None:
				self.wpa_handshakes.append(handshake)

	def load_half_wpa_handshakes(self):
		del self.half_wpa_handshakes[:]
		for handshake in os.listdir("data/wpa_half_handshakes"):
			handshake = self._parse_filename_to_handshake(handshake, True)
			if handshake != None:
				self.half_wpa_handshakes.append(handshake)

	def _parse_filename_to_handshake(self, handshake, is_half):
		try:
			handshake_name = handshake.split(".")[0]
			ssid = handshake_name.split("_")[1]
			client_mac = handshake_name.split("_")[2]
			return 	WPAHandshake(len(self.half_wpa_handshakes), ssid, client_mac, os.path.abspath("data/wpa_half_handshakes/"+handshake)) if is_half else \
					WPAHandshake(len(self.wpa_handshakes), ssid, client_mac, os.path.abspath("data/wpa_handshakes/"+handshake))
		except: pass

	def set_wpa_cracker(self, wpa_cracker):
		self.wpa_cracker = wpa_cracker

	def prepare_wpa_cracker(self, id, is_half):
		handshake = self.half_wpa_handshakes[id] if is_half else self.wpa_handshakes[id]
		self.wpa_cracker.ssid = handshake.ssid
		self.wpa_cracker.pcap_file = handshake.location


	def launch_handshake_cracker(self, id, is_half, wpa_cracker = None):
		if not self.wpa_cracker and not wpa_cracker:
			print "[-] WPA Cracker not yet set."
			return
		if wpa_cracker:
			self.wpa_cracker = wpa_cracker

		try:
			id = int(id)
		except:
			print "[-] ID must be an integer"
			return

		if (is_half and (id > len(self.half_wpa_handshakes) or id < 0)) or (id > len(self.wpa_handshakes)):
			print "[-] Chosen index is out of bounds"
			return

		self.prepare_wpa_cracker(id, is_half)
		self.wpa_cracker.spawn_cracker()


