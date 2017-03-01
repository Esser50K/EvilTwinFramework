from sslstripspawner import SSLStripSpawner

class MITMFSpawner(SSLStripSpawner):

	def __init__(self, config):
		super(MITMFSpawner, self).__init__(config)
		self.name = "mitmf"
		self.calling = self.system_location + "/mitmf.py"
		