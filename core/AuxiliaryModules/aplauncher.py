
import os
import pyric.pyw as pyw
from etfexceptions import InvalidConfigurationException
from utils.utils import FileHandler, DEVNULL
from netaddr import EUI, OUI
from subprocess import Popen, check_output
from textwrap import dedent
from threading import Thread
from utils.utils import FileHandler, DEVNULL
from time import sleep

class APLauncher(object):

	def __init__(self, hostapd_config_path):
		self.hostapd_config_path = hostapd_config_path

		self.ap_running = False
		self.ap_process = None

		self.connected_clients_updator = None
		self.connected_clients = []

		self.file_handler = None

	# TODO: Add support for multiple SSIDs! 
	def write_hostapd_configurations(self,  interface="wlan0", 
											ssid=None, 
											bssid=None, 
											channel="1", 
											hw_mode="g", 
											encryption=None, 
											auth="PSK", 
											cipher="CCMP", 
											password=None):
		self.cleanup()

		try:
			self.file_handler = FileHandler(self.hostapd_config_path, backup=False)
		except Exception as e:
			print e
			return False

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

		# Spoof bssid from other access points
		if bssid:
			configurations += "bssid={bssid}\n".format(bssid=bssid)

		# May even want to mirror the encryption type and key 
		# so hosts can automatically connect if it is a known network
		if encryption:
			if ("wpa" in encryption):
				if password is None: 
					raise InvalidConfigurationException("Must specify a password when choosing wpa or wpa2 encryption!\n")
				if len(password) < 8 or len(password) > 63: 
					raise InvalidConfigurationException("Specified password must have at least 8 printable digits and a maximum of 63\n")

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
				configurations += "wpa_passphrase={password}\n".format(password=password)   # password minimum is 8 digits
				configurations += "wpa_key_mgmt=WPA-{auth}\n".format(auth=auth)             # authentication method: PSK or EAP
				configurations += "wpa_pairwise={cipher}\n".format(cipher=cipher)           # cipher: CCMP or TKIP

			elif encryption == "wep":
				if not (len(password) == 5 or len(password) == 13 or len(password) == 16):
					raise InvalidConfigurationException("Specified must have 5 or 13 or 16 digits for WEP\n")

				configurations += "wep_default_key=0\n"
				configurations += "wep_key0=\"{key}\"".format(key=password)


		self.file_handler.write(configurations)
		return True

	def start_access_point(self, interface):
		print "[+] Starting hostapd background process"
		self.ap_process = Popen("hostapd {config_path}".format( config_path=self.hostapd_config_path).split(), 
								stdout=DEVNULL,
								stderr=DEVNULL)

		self.ap_running = True
		self.connected_clients_updator = Thread(target=self.update_connected_clients, args=(interface, ))
		self.connected_clients_updator.start()

	def stop_access_point(self, wait = True):
		if self.ap_process != None:
			print "[+] Killing hostapd background process"
			self.ap_process.send_signal(9)  # Send SIGINT to process running hostapd
			self.ap_process = None

		os.system('service hostapd stop')
		os.system('pkill hostapd')      # Cleanup
		self.ap_running = False
		if self.connected_clients_updator != None:
			if wait:
				self.connected_clients_updator.join()
			self.connected_clients_updator = None

	def cleanup(self):
		if self.file_handler:
			self.file_handler.restore_file()
			self.file_handler = None

	def update_connected_clients(self, interface):
		fail_count = 0
		while self.ap_running:
			if not self._parse_connected_clients(interface):
				fail_count += 1

			if fail_count > 3:
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

		temp_clients = []
		# At this point a client is a list of arguments to be parsed
		for client in client_dump:
			client_mac                  = client[0].split()[0].strip()
			client_name, client_ip      = self._get_ip_from_mac(interface, client_mac)
			inactivity_time             = client[1].split(":")[1].strip()
			rx_packets                  = client[3].split(":")[1].strip()
			tx_packets                  = client[5].split(":")[1].strip()
			signal                      = client[8].split(":")[1].strip()
			tx_bitrate                  = client[10].split(":")[1].strip()
			rx_bitrate                  = client[11].split(":")[1].strip()
			id = len(temp_clients)

			client = Client(id, client_name, client_mac, client_ip, inactivity_time, 
							rx_packets, tx_packets, rx_bitrate, tx_bitrate, signal)

			if client not in self.connected_clients:
				print "[+] New connected client with -> ip: {ip}, mac: {mac} ({vendor})".format(ip=client_ip, 
																								mac=client_mac, 
																								vendor=client.vendor)
			temp_clients.append(client)

		self.connected_clients = temp_clients
		return True
		

	def _get_ip_from_mac(self, interface, mac):
		arp_output = check_output("arp -a -i {}".format(interface).split()).split("\n")
		for line in arp_output:
			if mac.lower() in line.lower():
				try:
					device_name, device_ip = map(str.strip, (line.split()[0:2]))
					device_ip = device_ip[1:-1] # Cut the enclosing parenthesis off: (0.0.0.0) -> 0.0.0.0
					return (device_name, device_ip)
				except Exception as e:
					print e
					print "[-] Problem occurred while parsing arp output."

		return (None, None)



class Client(object):

	def __init__(self,  id, name, mac_address, ip_address, inactivity_time, 
						rx_packets, tx_packets,
						rx_bitrate, tx_bitrate,
						signal):
		self.id = id
		self.name = name
		self.mac_address = mac_address
		self.ip_address = ip_address
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
