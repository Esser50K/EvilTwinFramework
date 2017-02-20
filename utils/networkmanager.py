'''
This module contains the classes to represent
wireless interfaces as well as methods to handle them
and their information
'''

import os
import pyric.pyw as pyw
from utils import NetUtils, FileHandler
from textwrap import dedent

class NetworkCard(object):

	def __init__(self, interface):

		self.interface = interface
		self.card = pyw.getcard(interface)
		self.modes = pyw.devmodes(self.card)
		self.original_mac = pyw.macget(self.card)

		# Important capabilities
		self._ap_mode_support = "AP" in self.modes
		self._monitor_mode_support = "monitor" in self.modes

	def set_txpower(self, dbm):
		pyw.txset(self.card, 'fixed', dbm)

	def get_txpower(self):
		return pyw.txget(self.card)

	def set_mode(self, mode):
		try:
			pyw.down(self.card)
			pyw.modeset(self.card, mode)
			pyw.up(self.card)
		except Exception as e:
			print e, "\n[-] Unable to set mode on {}".format(self.interface)
			return False

	def get_mode(self):
		try:
			return pyw.modeget(self.card)
		except Exception:
			return None

	def set_mac(self, mac):
		try:
			pyw.down(self.card)
			pyw.macset(self.card, mac)
			pyw.up(self.card)
			return True
		except Exception as e:
			print e, "\n[-] Unable to set mac on {}".format(self.interface)
			return False

	def get_mac(self):
		return pyw.macget(self.card)

	def ifconfig(self, ip, netmask=None, broadcast=None):
		pyw.up(self.card)
		pyw.ifaddrset(self.card, ip, netmask, broadcast)

	def get_ip(self):
		return pyw.ifaddrget(self.card)[0]

	def get_subnet(self):
		ip_split = self.get_ip().split('.')
		netmask_split = self.get_mask().split('.')
		subnet = [0, 0, 0, 0]
		for i in range(4):
			subnet[i] = ip_split[i] if netmask_split[i] != "0" else "0"

		return ".".join(subnet)

	def get_mask(self):
		return pyw.ifaddrget(self.card)[1]

	def get_bcast(self):
		return pyw.ifaddrget(self.card)[2]

	def get_channel(self):
		return pyw.chget(self.card)

	def set_channel(self, channel):
		pyw.chset(self.card, channel)

	def get_available_channels(self):
		return pyw.devchs(self.card)

	def set_mtu_size(self, nbytes):
		os.system('ifconfig {interface} mtu {size}'.format( interface=self.interface,
															size=nbytes))

	def get_connected_clients(self):
		if pyw.modeget(self.card) == 'AP':
			os.system("iw dev {} station dump".format(self.interface))
		else:
			print "[-] '{}' is not on AP mode".format(self.interface)


class NetworkManager(object):

	def __init__(self, networkmanager_config_path='/etc/NetworkManager/NetworkManager.conf'):
		self.interfaces = pyw.interfaces()
		self.netcards = { interface: NetworkCard(interface) for interface in pyw.winterfaces() }
		self.interfaces_to_ignore = []
		self.nm_config_file = networkmanager_config_path
		self.file_handler = None

	def add_interface_to_ignore(self, interface):
		self.interfaces_to_ignore.append(interface)

	def iptables_redirect(self, from_if, to_if):
		card = self.get_netcard(from_if) # Get NetCard object

		if card != None:
			NetUtils().flush_iptables()
			NetUtils().accept_forwarding(from_if)
			NetUtils().set_postrouting_interface(to_if)
			NetUtils().add_routing_rule(card.get_subnet(), card.get_mask(), card.get_ip())

	def configure_interface(self, interface, ip, netmask=None, broadcast=None, mtu=1800):
		card = self.get_netcard(interface) # Get NetCard object

		if card != None:
			card.ifconfig(ip, netmask, broadcast)
			card.set_mtu_size(mtu)

	def set_mac_and_unmanage(self, interface, mac, retry = False, virtInterfaces = 0):
		card = self.get_netcard(interface)

		# Runs at least once, if retry is flagged 
		# it will try to reset the interface and repeat the process
		while(True):
			if card != None:
				if not card.set_mac(mac):
					return False
					
				if not self.network_manager_ignore(interface, mac, virtInterfaces):
					return False

				os.system("service NetworkManager restart") # Restarting NetworkManager service
				if pyw.macget(card.card) == mac:
					return True

			if not retry:
				break

			print "[-] Unable to set mac and unmanage, resetting interface and retrying."
			retry = False
			card = NetworkCard(interface)
			if card.get_mode() != 'managed':
				card.set_mode('managed')
		
		return False

	# NetworkManager is usually a conflicting process, 
	# but we can configure it to ignore the interface 
	# we use as access point or to sniff packets
	def network_manager_ignore(self, interface, mac_address, virtInterfaces): 
		mac_address = mac_address[:-1] + "0"
		interface_ignore_string = interface

		for i in range(virtInterfaces):
			interface_ignore_string += ",mac:{}".format(mac_address[:-1] + str(i+1))
		for iface in self.interfaces_to_ignore:
			interface_ignore_string += ",interface-name:{}".format(iface)

		try:
			ignore_config = dedent( """
									[main]
									plugins=ifupdown,keyfile

									[ifupdown]
									managed=false

									[keyfile]
									unmanaged-devices=mac:{mac_address},interface-name:{ignore_interfaces}
									""".format( mac_address=mac_address,
												ignore_interfaces=interface_ignore_string
												))

			self.cleanup_filehandler()
			self.file_handler = FileHandler(self.nm_config_file)
			self.file_handler.write(ignore_config)
		except Exception as e:
			print e
			return False

		return True

	def get_netcard(self, interface):
		netcard = None
		try:
			try:
				netcard = self.netcards[interface]
			except KeyError:
				# Check if it was plugged in at runtime
				self.netcards = { interface: NetworkCard(interface) for interface in pyw.winterfaces() }
				netcard = self.netcards[interface]
		except KeyError:
			print "[-] Interface: '{}' does not exist".format(interface)
			return None
		
		return netcard



	def cleanup_filehandler(self):
		if self.file_handler:
			self.file_handler.restore_file()
			self.file_handler = None

	def reset_interfaces(self):
		for card in self.netcards:
			self.netcards[card].set_mac(self.netcards[card].original_mac)
			self.netcards[card].set_mode('managed')

	def cleanup(self):
		NetUtils().flush_iptables()
		self.cleanup_filehandler()
		self.reset_interfaces()



