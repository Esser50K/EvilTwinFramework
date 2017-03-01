"""
This module has the base class for MITM custom plugins
Every MITM Plugin must be a subclass of MITMPlugin
"""
import sys
sys.path.append('./core')
from ConfigurationManager.configmanager import ConfigurationManager

class MITMPlugin(object):

	def __init__(self, name):
		self.name = name
		self.config = ConfigurationManager("./core/ConfigurationManager/etf.conf").config["etf"]["mitmproxy"]["mitmplugins"][name]

	def get_config(self, key):
		try:
			return self.config[key]
		except:
			print "[-] MITMPlugin Error: Key '{}' does not exist for '{}'".format(key, self.name)
			return None

	def request(self, flow):
		pass

	def response(self, flow):
		pass
