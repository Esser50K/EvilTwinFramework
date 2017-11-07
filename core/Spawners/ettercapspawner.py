from spawner import Spawner

class EttercapSpawner(Spawner):

    def __init__(self, config, name = "ettercap"):
        super(EttercapSpawner, self).__init__(config, name)
        self.calling = self.system_location + "/lua/core/ettercap.lua"
