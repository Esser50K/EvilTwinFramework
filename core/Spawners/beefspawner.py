from spawner import Spawner

class BeefSpawner(Spawner):

    def __init__(self, name = "beef-xss"):
        super(BeefSpawner, self).__init__(name)
        self.calling = self.system_location + "/beef"
