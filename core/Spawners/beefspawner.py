from spawner import Spawner

class BeefSpawner(Spawner):

	def __init__(self, system_location):
		super(BeefSpawner, self).__init__(system_location)
		self.name = "beef-xss"
		self.calling = system_location + "/beef"

	def restore_process(self):
		super(BeefSpawner, self).restore_process()