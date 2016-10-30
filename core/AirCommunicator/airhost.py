'''
This module is responsible for lauching the access point.
It makes use of hostapd and dnsmasq to provide an access point
and dhcp and dns services
'''

import os
from AuxiliaryModules.dnsmasqhandler import DNSMasqHandler
from AuxiliaryModules.aplauncher import APLauncher
from etfexceptions import MissingConfigurationFileException


class AirHost(object):

    def __init__(self, hostapd_config_path, dnsmasq_config_path):
        # Mandatory configuration files to start the access point successfully
        if (dnsmasq_config_path == None or hostapd_config_path == None) :
            raise MissingConfigurationFileException("dnsmasq and hostapd configuration files must be specified\n \
                                                    either by argument in the command line or in the etf.conf file")

        self.aplauncher = APLauncher(hostapd_config_path)
        self.dnsmasqhandler = DNSMasqHandler(dnsmasq_config_path)

        self.running_interface = None

        self.plugins = []

    def add_plugin(self, airhost_plugin):
        self.plugins.append(airhost_plugin)

    def start_access_point(self, interface):
        print "[+] Killing already started processes and restarting network services"
        self.stop_access_point(False) # Restarting services helps avoiding some conflicts with dnsmasq

        for plugin in self.plugins:
            plugin.start()

        self.aplauncher.start_access_point(interface)
        if not self.dnsmasqhandler.start_dnsmasq():
            print "[-] Error starting dnsmasq, aborting AP launch"
            return False

        self.running_interface = interface
        print "[+] Access Point launched successfully"
        return True

    def stop_access_point(self, free_plugins = True):
        print "[+] Stopping dnsmasq and hostapd services"
        self.aplauncher.stop_access_point()
        self.dnsmasqhandler.stop_dnsmasq()
        self.running_interface = None
        print "[+] Access Point stopped, restarting network services..."
        os.system('service networking restart')
        os.system('service NetworkManager restart')

        if free_plugins:
            for plugin in self.plugins:
                plugin.restore()

    def is_running(self):
        return self.running_interface != None

    def cleanup(self):
        self.dnsmasqhandler.cleanup()
        self.aplauncher.cleanup()