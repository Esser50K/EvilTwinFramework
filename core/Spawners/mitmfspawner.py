from sslstripspawner import SSLStripSpawner

class MITMFSpawner(SSLStripSpawner):

    def __init__(self, name = "mitmf"):
        super(MITMFSpawner, self).__init__(name)
        self.calling = self.system_location + "/mitmf.py"
