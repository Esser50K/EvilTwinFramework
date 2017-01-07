"""
Template Plugin class to be subclassed
"""

class Plugin(object):

	def __init__(self):
		pass

	def restore(self):
		"""
		To be called when done with main service as cleanup function
		"""
		pass

class AirScannerPlugin(Plugin):

	def __init__(self):
		super(AirScannerPlugin, self).__init__()

	def handle_packet(self, packet):
		pass


class AirHostPlugin(Plugin):

	def __init__(self):
		super(AirHostPlugin, self).__init__()

	def start(self):
		pass

class AirDeauthorPlugin(Plugin):

	def __init__(self):
		super(AirDeauthorPlugin, self).__init__()

	def pre_deauth(self):
		pass

	def post_deauth(self):
		pass

