"""
This module handles custom mitm scripts using mitmproxy inline scripts
"""

import sys, os
from MITMPlugins.mitmplugin import MITMPlugin
from MITMPlugins.beefinjector import BeefInjector
from MITMPlugins.peinjector import PeInjector
from MITMPlugins.downloadreplacer import DownloadReplacer

from mitmproxy import controller, proxy, platform, options
from mitmproxy.proxy.server import ProxyServer
from ConfigurationManager.configmanager import ConfigurationManager
from subprocess import Popen, PIPE
from utils.utils import NetUtils
from threading import Thread


class ThreadController(Thread):
	def __init__(self,main ,parent=None):
		super(ThreadController, self).__init__(parent)
		self.main = main

	def run(self):
		try:
			controller.Master.run(self.main)
		except Exception as e:
			print "[-] mitmproxy crashed:", e
			self.main.shutdown()

class EvilInTheMiddleHandler(controller.Master):

	def __init__(self, options, server):
		super(EvilInTheMiddleHandler, self).__init__(options)
		if server:
			self.add_server(server)
		self.plugins		= []

	def run(self):
		self.thread = ThreadController(self)
		self.thread.start()

	@controller.handler
	def request(self, flow):
		for p in self.plugins:
			try:
				p.request(flow)
			except Exception:
				pass

	@controller.handler
	def requestheaders(self, flow):
		for p in self.plugins:
			try:
				p.requestheaders(flow)
			except Exception:
				pass

	@controller.handler
	def response(self, flow):
		for p in self.plugins:
			try:
				p.response(flow)
			except Exception:
				pass

	@controller.handler
	def responseheaders(self, flow):
		for p in self.plugins:
			try:
				p.responseheaders(flow)
			except Exception:
				pass

	@controller.handler
	def log(self, l):
		pass

	@controller.handler
	def clientconnect(self, root_layer):
		pass

	@controller.handler
	def clientdisconnect(self, root_layer):
		pass

	@controller.handler
	def serverconnect(self, server_conn):
		pass

	@controller.handler
	def serverdisconnect(self, server_conn):
		pass

	@controller.handler
	def next_layer(self, top_layer):
		pass

	@controller.handler
	def error(self, f):
		pass

	@controller.handler
	def websocket_handshake(self, f):
		pass

	def handle_intercept(self, f):
		pass

	def handle_accept_intercept(self, f):
		pass

	@controller.handler
	def tcp_start(self, flow):
		pass

	@controller.handler
	def tcp_message(self, flow):
		pass

	@controller.handler
	def tcp_error(self, flow):
		pass

	@controller.handler
	def tcp_end(self, flow):
		pass


class EvilInTheMiddle(object):

	def __init__(self):
		self.listen_host		= None
		self.listen_port		= 8080
		self.ssl				= False			# If True port 443 will be redirected to listen_port
		self.certs				= []
		self.certs_base_path	= ConfigurationManager().config["etf"]["mitmproxy"]["mitm_certs_base_path"]
		self.plugins_base_path	= ConfigurationManager().config["etf"]["mitmproxy"]["mitmplugins"]["mitm_plugins_base_path"]
		self.master_handler 	= None
		self.set_rules			= False
		self.running 			= False

	def pass_config(self, 	listen_host = None, listen_port = 8080,
							ssl = False, client_cert = None, certs = [], 
							plugins = []):
		self.listen_host 	= listen_host
		self.listen_port 	= listen_port
		self.ssl 			= ssl
		self.client_cert 	= client_cert
		self.certs 			= certs
		self.plugins 		= plugins
		self.set_rules		= False

	def start(self):
		if not self.running:
			print "[+] Configuring iptable rules"
			self._prepare_iptable_rules()
			print "[+] Preparing master handler"
			self._prepare_handler()
			print "[+] Starting master handler"
			self.master_handler.run()
			self.running = True

	def stop(self):
		if self.running:
			print "[+] Clearing iptable rules"
			self._clear_iptable_rules()
			if self.master_handler != None:
				print "[+] Shutting down the master handler"
				for plugin in self.master_handler.plugins:
					plugin.cleanup()

				self.master_handler.shutdown()
			self.running = False

	def _prepare_handler(self):
		proxy_opts 		= options.Options(
							clientcerts=self.client_cert,
							certs=self.certs,
							#listen_host=self.listen_host,
							listen_port=self.listen_port,
							mode='transparent',
							)
		proxy_config 	= proxy.ProxyConfig(proxy_opts)
		proxy_server = ProxyServer(proxy_config)
		self.master_handler = EvilInTheMiddleHandler(proxy_opts, proxy_server)

		# Initialize plugins. Same method as in WiFi-Pumpkin
		for plugin in MITMPlugin.__subclasses__():
			plugin_instance = plugin()
			if plugin_instance.name in self.plugins:
				self.master_handler.plugins.append(plugin_instance)
				plugin_instance.setup()
				print "[+] Successfully loaded '{}' plugin.".format(plugin_instance.name)

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