from sslstripspawner import SSLStripSpawner

class MITMFSpawner(SSLStripSpawner):

	def __init__(self, system_location, redirection_port="10000"):
		super(MITMFSpawner, self).__init__(system_location, redirection_port)
		self.name = "mitmf"
		self.calling = system_location + "/mitmf.py"
		