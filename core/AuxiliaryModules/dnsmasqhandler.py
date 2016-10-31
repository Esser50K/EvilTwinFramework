"""
This class is responsible for configuring all pages to spoof, 
adding them to the hosts file and setting them up in apache
with help of the httpserver class as well as configuring dnsmasq
"""

import os
from utils.utils import FileHandler
from textwrap import dedent

class DNSMasqHandler(object):

	def __init__(self, dnsmasq_config_path):
		self.dnsmasq_config_path = dnsmasq_config_path

		self.captive_portal_mode = False
		self.dnsmasq_running = False

		self.file_handler = None

	def set_captive_portal_mode(self, captive_portal_mode):
		self.captive_portal_mode = captive_portal_mode

	def write_dnsmasq_configurations(self, interface, ip_gw, dhcp_range=[], nameservers=[]):
		# Argument cleanup
		if type(nameservers) is not list:
			nameservers = [nameservers]

		configurations = dedent("""
								interface={interface}
								dhcp-range={dhcp_start}, {dhcp_end}, 12h
								dhcp-option=3,{ip_gw}
								dhcp-option=6,{ip_gw}
								""".format( interface = interface,
											ip_gw = ip_gw,
											dhcp_start = dhcp_range[0],
											dhcp_end = dhcp_range[1]))

		if self.captive_portal_mode:
			configurations += "no-resolv\n"
			configurations += "address=/#/{ip_gw}\n".format(ip_gw = ip_gw)
		else:
			for server in nameservers:
				configurations += "server={server}\n".format(server = server)

		return self._safe_write_config(configurations, self.dnsmasq_config_path)
		

	def _safe_write_config(self, configurations, config_path):
		if self.file_handler:
			self.file_handler.write(configurations)
		else:
			self.file_handler = FileHandler(config_path)
			self.file_handler.write(configurations)


	def start_dnsmasq(self):
		print "[+] Starting dnsmasq service"
		if not os.system('service dnsmasq start') == 0:
			return False

		self.dnsmasq_running = True
		return True

	def stop_dnsmasq(self):
		os.system('service dnsmasq stop')
		os.system('pkill dnsmasq')      # Cleanup
		self.dnsmasq_running = False

	def cleanup(self):
		self.file_handler.restore_file()