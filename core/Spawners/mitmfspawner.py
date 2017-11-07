from sslstripspawner import SSLStripSpawner

class MITMFSpawner(SSLStripSpawner):

    def __init__(self, config, name = "mitmf"):
        super(MITMFSpawner, self).__init__(config, name)
        self.calling = self.system_location + "/mitmf.py"
