from spawner import Spawner

class EttercapSpawner(Spawner):

    def __init__(self, name = "ettercap"):
        super(EttercapSpawner, self).__init__(name)
        self.calling = self.system_location + "/lua/core/ettercap.lua"
