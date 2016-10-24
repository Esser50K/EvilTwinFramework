"""
This class is responsible for configuring all pages to spoof, 
adding them to the hosts file and setting them up in apache
with help of the httpserver class
"""

import os
from utils.utils import FileHandler
from textwrap import dedent

class DNSSpoofer(object):

	def __init__(self, dnsmasq_config_path, hosts_config_path, spoofpages = []):
		self.hosts_config_path = hosts_config_path
		self.dnsmasq_config_path = dnsmasq_config_path

		self.spoofpages = spoofpages if type(spoofpages) is list else [spoofpages]

		self.captive_portal_mode = False
		self.dnsmasq_running = False
		self.httpserver_running = False


		self.httpserver = None
		self.file_handlers = []


	def set_captive_portal_mode(self, captive_portal_mode):
		self.captive_portal_mode = captive_portal_mode

	def set_http_server(self, server):
		self.httpserver = server

	def has_http_server(self):
		return self.httpserver != None

	def add_page_to_spoof(self, page_name):
		for page in os.listdir("data/spoofpages/"):
			if page_name in page:
				self.spoofpages.append(page)
				print "[+] Added {page} to spoof list".format(page = page)
				return

		print "[-] Page '{}' not found in 'data/spoofpages/' folder."

	def _cleanup_misconfigured_pages(self):
		pages = []
		for page in self.spoofpages:
			for spoofpage in os.listdir("data/spoofpages/"):
				if page in spoofpage:
					pages.append(spoofpage)
		self.spoofpages = pages


	def map_spoofing_pages(self, redirection_ip):
		file_handler = self._add_filehandler(self.hosts_config_path)
		self._cleanup_misconfigured_pages()
		conf_string = ""
		if self.captive_portal_mode:
			page = self.spoofpages[0]
			conf_string += "{ip}\t{domain}\t{alias}\n".format(ip = redirection_ip, 
															domain = page,
															alias = "\t".join(self._create_alias_list(page)))
			conf_string += "{ip} *.*.*\n".format(ip = redirection_ip)
			print "[+] Mapped '{domain}' to {ip} as captive portal".format(domain = page, ip = redirection_ip)
		else:
			for page in self.spoofpages:
				conf_string += "{ip}\t{domain}\t{alias}\n".format(ip = redirection_ip, 
																domain = page,
																alias = "\t".join(self._create_alias_list(page)))
				print "[+] Mapped '{domain}' to {ip}".format(domain = page, ip = redirection_ip)
		file_handler.write(conf_string)

	def setup_spoofing_pages(self):
		if not self.has_http_server():
			print "[-] No HTTP Server added to DNSSpoofer, cannot setup spoofing"
			return False

		self._cleanup_misconfigured_pages()
		for page in self.spoofpages:
			self.httpserver.add_site(page)
			self.httpserver.configure_page_in_apache(	domain_name = page, 
														domain_alias = self._create_alias_list(page),
														ssl = True,
														captive_portal_mode = True)
		return self.httpserver.start_server(True)

	def _create_alias_list(self, domain):
		aliases = []
		splitted_domain = domain.split(".")
		if len(splitted_domain) >= 3:
			for i in range(len(splitted_domain) - 2):
				aliases.append(".".join(splitted_domain[i+1:]))

		return aliases

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
		for server in nameservers:
			configurations += "server={server}\n".format(server = server)

		if self.captive_portal_mode:
			configurations += "no-resolv\n"
			configurations += "address=/#/{ip_gw}\n".format(ip_gw = ip_gw)

		return self._safe_write_config(configurations, self.dnsmasq_config_path)
		

	def _safe_write_config(self, configurations, config_path):
		try: # Look for dnsmasq file config handler
			file_handler = None
			for fhandler in self.file_handlers:
				if fhandler.current_file == config_path:
					file_handler = fhandler

			if not file_handler:
				file_handler = FileHandler(config_path)
			file_handler.write(configurations)
			self.file_handlers.append(file_handler)
		except Exception as e:
			print e
			return False

		return True

	def start_spoofing(self, spoof_ip):
		if not self.has_http_server():
			print "[-] No HTTP Server added to DNSSpoofer, cannot spoof pages"
			return False

		self.httpserver.reset_conf()
		self.map_spoofing_pages(spoof_ip)
		self.setup_spoofing_pages()
		self.httpserver.start_server()

	def stop_spoofing(self):
		if self.has_http_server():
			self.httpserver.reset_conf()
			self.httpserver.start_server(False)

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
		for fhandler in self.file_handlers:
			fhandler.restore_file()
		del self.file_handlers[:] # empty the file handler list

	def _add_filehandler(self, conf_file):
		try:
			file_handler = None
			for fhandler in self.file_handlers:
				if fhandler.current_file == conf_file:
					file_handler = fhandler

			if not file_handler:
				file_handler = FileHandler(conf_file, backup=False)
			self.file_handlers.append(file_handler)
			return file_handler
		except Exception as e:
			print e
			return False