from sslstripspawner import SSLStripSpawner

class MITMFSpawner(SSLStripSpawner):

	def __init__(self):
		super(MITMFSpawner, self).__init__()
		self.name = "mitmf"
		self.calling = self.system_location + "/mitmf.py"
		