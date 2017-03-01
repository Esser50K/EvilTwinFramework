from spawner import Spawner

class EttercapSpawner(Spawner):

	def __init__(self, config):
		super(EttercapSpawner, self).__init__(config)
		self.name = "ettercap"
		self.calling = self.system_location + "/lua/core/ettercap.lua"

	def restore_process(self):
		super(EttercapSpawner, self).restore_process()