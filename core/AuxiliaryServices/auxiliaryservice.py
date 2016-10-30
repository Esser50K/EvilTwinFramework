"""
Template Plugin class to be subclassed
"""

class AuxiliaryService(object):

	def __init__(self):
		pass

	def restore(self):
		"""
		To be called when done with main service as cleanup function
		"""
		pass

class AirScannerAuxService(AuxiliaryService):

	def __init__(self):
		super(AirScannerAuxService, self).__init__()

	def handle_packet(self, packet):
		pass


class AirHostAuxService(AuxiliaryService):

	def __init__(self):
		super(AirHostAuxService, self).__init__()

	def start(self):
		pass