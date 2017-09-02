from spawner import Spawner

class BeefSpawner(Spawner):

    def __init__(self):
        super(BeefSpawner, self).__init__("beef-xss")
        self.calling = self.system_location + "/beef"
