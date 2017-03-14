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

class AirDeauthorPlugin(Plugin):

	def __init__(self, name):
		super(AirDeauthorPlugin, self).__init__(name)

	def pre_deauth(self):
		pass

	def post_deauth(self):
		pass

