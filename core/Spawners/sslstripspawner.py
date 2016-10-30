from ConfigurationManager.configmanager import ConfigurationManager
from utils.utils import NetUtils
from spawner import Spawner
from utils.utils import NetUtils

class SSLStripSpawner(Spawner):

    def __init__(self, system_location, redirection_port="10000"):
        super(SSLStripSpawner, self).__init__(system_location)
        self.name = "sslstrip"
        self.calling = system_location + "/sslstrip.py"
        self.redirection_port=redirection_port

    def setup_process(self):
        try:
            self.redirection_port = ConfigurationManager().config["etf"]["spawner"]["tcp_redirection_port"]
        except KeyError:
            pass
        
        NetUtils().set_port_redirection_rule("tcp", "80", self.redirection_port, True) # Adds the iptable rule
        #NetUtils().set_port_redirection_rule("tcp", "443", self.redirection_port, True) # Adds the iptable rule

    def restore_process(self):
        airhost_configs  = ConfigurationManager().config["etf"]["aircommunicator"]["airhost"]
        ap_interface        = airhost_configs["ap_interface"]
        internet_interface  = airhost_configs["internet_interface"]

        NetUtils().flush_iptables()
        NetUtils().accept_forwarding(ap_interface)
        NetUtils().set_postrouting_interface(internet_interface)
        #NetUtils().set_port_redirection_rule("tcp", "80", self.redirection_port, False) # Deletes the iptable rule