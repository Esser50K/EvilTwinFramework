from spawner import Spawner

class BeefSpawner(Spawner):

    def __init__(self, config, name = "beef-xss"):
        super(BeefSpawner, self).__init__(config, name)
        self.calling = self.system_location + "/beef"
