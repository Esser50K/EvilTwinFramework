from spawner import Spawner

class EttercapSpawner(Spawner):

	def __init__(self):
		super(EttercapSpawner, self).__init__("ettercap")
		self.calling = self.system_location + "/lua/core/ettercap.lua"