from utils.utils import NetUtils
from spawner import Spawner

class SSLStripSpawner(Spawner):
    """
    Spawner for the ssltrip program.
    """

    def __init__(self, config, name = "sslstrip"):
        super(SSLStripSpawner, self).__init__(config, name)
        self.calling = self.system_location + "/sslstrip.py"

    def setup_process(self):
        if not self.is_set_up:
            NetUtils().set_port_redirection_rule("tcp", "80", self.config["tcp_redirection_port"], True)  # Adds the iptable rule
            NetUtils().set_port_redirection_rule("tcp", "443", self.config["tcp_redirection_port"], True)  # Adds the iptable rule
        super(SSLStripSpawner, self).setup_process()

    def restore_process(self):
        if not self.is_set_up:
            NetUtils().set_port_redirection_rule("tcp", "80", self.config["tcp_redirection_port"], False)  # Deletes the iptable rule
            NetUtils().set_port_redirection_rule("tcp", "443", self.config["tcp_redirection_port"], False)  # Deletes the iptable rule
        super(SSLStripSpawner, self).restore_process()
