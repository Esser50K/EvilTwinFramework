"""
This class is responsible for configuring all pages to spoof,
adding them to the hosts file and setting them up in apache
with help of the httpserver class as well as configuring dnsmasq
"""

import os
from utils.utils import FileHandler
from textwrap import dedent
from time import sleep

class DNSMasqHandler(object):

    def __init__(self, dnsmasq_config_path):
        self.dnsmasq_config_path = dnsmasq_config_path

        self.captive_portal_mode = False
        self.dnsmasq_running = False

        self.file_handler = None

    def set_captive_portal_mode(self, captive_portal_mode):
        self.captive_portal_mode = captive_portal_mode

    def write_dnsmasq_configurations(self, interface, ip_gw, dhcp_range=[], nameservers=[], virtInterfaces = 0):
        # Argument cleanup
        if type(nameservers) is not list:
            nameservers = [nameservers]

        dhcp_range_string = "\ndhcp-range={interface}, {dhcp_start}, {dhcp_end}, 12h".format(interface  = interface,
                                                                                             dhcp_start = dhcp_range[0],
                                                                                             dhcp_end   = dhcp_range[1])
        for i in range(virtInterfaces):
            dhcp_start = ".".join(dhcp_range[0].split(".")[0:2] + [str(int(dhcp_range[0].split(".")[2]) + i + 1)] + [dhcp_range[0].split(".")[3]])
            dhcp_end = ".".join(dhcp_range[1].split(".")[0:2] + [str(int(dhcp_range[1].split(".")[2]) + i + 1)] + [dhcp_range[1].split(".")[3]])
            dhcp_range_string += "\ndhcp-range={interface}_{index}, {dhcp_start}, {dhcp_end}, 12h".format(
                                                                                                    interface = interface,
                                                                                                    index = i,
                                                                                                    dhcp_start  = dhcp_start,
                                                                                                    dhcp_end    = dhcp_end)
        configurations = dedent("""
                                {dhcp_range}
                                dhcp-option=3,{ip_gw}
                                dhcp-option=6,{ip_gw}
                                """.format( dhcp_range = dhcp_range_string,
                                            interface = interface,
                                            ip_gw = ip_gw))
        configurations += "bind-interfaces\n"

        if self.captive_portal_mode:
            configurations += "no-resolv\n"
            configurations += "address=/#/{ip_gw}\n".format(ip_gw = ip_gw)
        else:
            for server in nameservers:
                configurations += "server={server}\n".format(server = server)

        return self._safe_write_config(configurations, self.dnsmasq_config_path)


    def _safe_write_config(self, configurations, config_path):
        if self.file_handler:
            self.file_handler.write(configurations)
        else:
            self.file_handler = FileHandler(config_path)
            self.file_handler.write(configurations)


    def start_dnsmasq(self):
        print "[+] Starting dnsmasq service"
        if not os.system('service dnsmasq restart') == 0:
            return False

        self.dnsmasq_running = True
        return True

    def stop_dnsmasq(self):
        os.system('service dnsmasq stop')
        os.system('pkill dnsmasq')      # Cleanup
        self.dnsmasq_running = False

    def cleanup(self):
        if self.file_handler is not None:
            self.file_handler.restore_file()
