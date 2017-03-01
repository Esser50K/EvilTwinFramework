from spawner import Spawner

class BeefSpawner(Spawner):

	def __init__(self, config):
		super(BeefSpawner, self).__init__(config)
		self.name = "beef-xss"
		self.calling = self.system_location + "/beef"

	def restore_process(self):
		super(BeefSpawner, self).restore_process()