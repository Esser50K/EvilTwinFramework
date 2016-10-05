from spawner import Spawner

class EttercapSpawner(Spawner):

    def __init__(self, system_location):
        super(EttercapSpawner, self).__init__(system_location)
        self.name = "ettercap"
        self.calling = system_location + "/lua/core/ettercap.lua"
