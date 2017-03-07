"""
This module has the base class for MITM custom plugins
Every MITM Plugin must be a subclass of MITMPlugin
"""
import sys
from ConfigurationManager.configmanager import ConfigurationManager

class MITMPlugin(object):

	def __init__(self, name):
		self.name = name
		self.config = ConfigurationManager().config["etf"]["mitmproxy"]["mitmplugins"][name]

	def setup(self):
		pass

	def cleanup(self):
		pass

	def get_config(self, key):
		try:
			return self.config[key]
		except:
			print "[-] MITMPlugin Error: Key '{}' does not exist for '{}'".format(key, self.name)
			return None

	def request(self, flow):
		pass

	def requestheaders(self, flow):
		pass

	def response(self, flow):
		pass

	def responseheaders(self, flow):
		pass
