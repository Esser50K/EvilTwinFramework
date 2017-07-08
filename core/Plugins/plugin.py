"""
Template Plugin class to be subclassed
"""
from ConfigurationManager.configmanager import ConfigurationManager

class Plugin(object):

	def __init__(self, name):
		self.name = name
		self.config = ConfigurationManager().config["etf"]["aircommunicator"]["plugins"][name]

	def restore(self):
		"""
		To be called when done with main service as cleanup method
		"""
		pass

class AirScannerPlugin(Plugin):

	def __init__(self, name):
		super(AirScannerPlugin, self).__init__(name)

	def pre_scanning(self):
		pass

	def handle_packet(self, packet):
		pass

	def post_scanning(self):
		pass


class AirHostPlugin(Plugin):

	def __init__(self, name):
		super(AirHostPlugin, self).__init__(name)

	def pre_start(self):
		pass

	def post_start(self):
		pass

	def stop(self):
		pass

class AirInjectorPlugin(Plugin):

	def __init__(self, name):
		super(AirInjectorPlugin, self).__init__(name)

	# this method receives either APs or Clients from the AirScanner
	# the specific injector will interpret what to do and create the corresponding packets
	def interpret_targets(self, targets):
		pass

	# the packet created in interpret_targets are sent in this method as the user specifies
	def inject_packets(self):
		pass

	def pre_injection(self):
		pass

	def post_injection(self):
		pass


