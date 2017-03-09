"""
Template Plugin class to be subclassed
"""
from ConfigurationManager.configmanager import ConfigurationManager

class Plugin(object):

	def __init__(self, name, type):
		self.name = name
		configs = ConfigurationManager().config["etf"]["aircommunicator"][type]["plugins"][name]
		try:
			self.config.keys()
		except:
			self.config = {}
		for key in configs.keys():
			self.config[key] = configs[key]

	def restore(self):
		"""
		To be called when done with main service as cleanup method
		"""
		pass

class AirScannerPlugin(Plugin):

	def __init__(self, name, type = "airscanner"):
		super(AirScannerPlugin, self).__init__(name, type)

	def handle_packet(self, packet):
		pass


class AirHostPlugin(Plugin):

	def __init__(self, name, type = "airhost"):
		super(AirHostPlugin, self).__init__(name, type)

	def start(self):
		pass

class AirDeauthorPlugin(Plugin):

	def __init__(self, name, type = "airdeauthor"):
		super(AirDeauthorPlugin, self).__init__(name, type)

	def pre_deauth(self):
		pass

	def post_deauth(self):
		pass

