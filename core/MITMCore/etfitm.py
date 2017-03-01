"""
This module handles custom mitm scripts using mitmproxy inline scripts
"""
import os
from ConfigurationManager.configmanager import ConfigurationManager
from subprocess import Popen, PIPE
from utils.utils import NetUtils

class EvilInTheMiddle(object):

	def __init__(self):
		self.listen_port 	= 8080
		self.bind_address 	= None
		self.ssl 			= False				# If True port 443 will be redirected to listen_port
		self.certs 			= []
		self.plugins 		= []
		self.mitm_process	= None
		self.plugins_base_path = 	os.getcwd() + "/" + \
									ConfigurationManager().config["etf"]["mitmproxy"]["mitmplugins"]["mitm_plugins_base_path"]
		self.certs_base_path = 	os.getcwd() + "/" + \
									ConfigurationManager().config["etf"]["mitmproxy"]["mitmplugins"]["mitm_certs_base_path"]

	def pass_config(self, 	listen_port = 8080, bind_address = None, 
							ssl = False, certs = [], 
							plugins = []):
		self.listen_port 	= listen_port
		self.bind_address 	= bind_address
		self.ssl 			= ssl
		self.certs 			= certs
		self.plugins 		= plugins
		self.set_rules		= False

	def start(self, background = False):
		mitmdump_arg_string = "mitmdump" + self._generate_mitmdump_arg_string()

		self._prepare_iptable_rules()
		if background:
			self.mitm_process = Popen(	mitmdump_arg_string.split(), 
										stdout=PIPE,
										stderr=PIPE
									 )
		else:
			self.mitm_process = Popen("sudo gnome-terminal -e".split() + ['{}'.format(mitmdump_arg_string)])


	def stop(self):
		self._clear_iptable_rules()
		if self.mitm_process != None:
			self.mitm_process.send_signal(9)
			os.system('pkill mitmdump')
			self.mitm_process = None

	def _prepare_iptable_rules(self):
		if not self.set_rules:
			NetUtils().set_port_redirection_rule("tcp", "80", self.listen_port)
			if self.ssl:
				NetUtils().set_port_redirection_rule("tcp", "443", self.listen_port)

			self.set_rules = True
			
	def _clear_iptable_rules(self):
		if self.set_rules:
			NetUtils().set_port_redirection_rule("tcp", "80", self.listen_port, add = False)
			if self.ssl:
				NetUtils().set_port_redirection_rule("tcp", "443", self.listen_port, add = False)

			self.set_rules = False

	def _generate_mitmdump_arg_string(self):
		mitmdump_arg_string = " -T -p {lport}".format(lport = self.listen_port)

		if self.bind_address != None:
			mitmdump_arg_string += " -b {baddress}".format(baddress = self.bind_address)

		# Insert Certificate args
		try:
			cert_arg_string = " "
			if len(self.certs) == 1:
				cert_arg_string += "--cert \"{cert_path}\" ".format(cert_path = self.certs[0])
			elif len(self.certs) > 1:
				for cert in self.certs:
					domain, cert_path = cert
					cert_arg_string += "--cert \"{domain}={cert_path}\" ".format(domain = domain, cert_path = cert_path)

			mitmdump_arg_string += cert_arg_string
		except Exception as e:
			print "[-] Errors in MITM certificate arguments. Follow syntax specified in conf file."
			print e

		# Insert script args
		try:
			script_arg_string = " "
			if len(self.plugins) > 0:
				for plugin in self.plugins:
					script_arg_string += "-s \"{plugin}\" ".format(plugin = self.plugins_base_path + plugin + ".py")

			mitmdump_arg_string += script_arg_string
		except Exception as e:
			print "[-] Errors in MITM certificate arguments. Follow syntax specified in conf file."
			print e

		return mitmdump_arg_string
