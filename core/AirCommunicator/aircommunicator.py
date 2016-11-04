# -*- coding: utf-8 -*-
'''
This is a wrapper class responsible for
everything that concerns air communications
such as setting up the access point as well
as sniffing the packets in the air
'''

from pyric.pyw import interfaces, winterfaces
from airhost import AirHost
from airscanner import AirScanner
from airdeauthor import AirDeauthenticator
from AuxiliaryModules.infoprinter import InfoPrinter, ObjectFilter
from AuxiliaryModules.httpserver import HTTPServer
from Plugins.dnsspoofer import DNSSpoofer
from Plugins.packetlogger import PacketLogger
from ConfigurationManager.configmanager import ConfigurationManager
from utils.networkmanager import NetworkManager, NetworkCard
from prettytable import PrettyTable
from textwrap import dedent
from threading import Thread

class AirCommunicator(object):

    def __init__(self):
        self.configs = ConfigurationManager().config["etf"]["aircommunicator"]
        self.config_files = ConfigurationManager().config["etf"]["config_location"]

        self.air_host = AirHost(self.config_files["hostapd_conf"], self.config_files["dnsmasq_conf"])
        self.air_scanner = AirScanner()
        self.air_deauthenticator = AirDeauthenticator()
        self.network_manager = NetworkManager(self.config_files["networkmanager_conf"])

        self.plugins = {"dnsspoofer"    : None,
                        "packetlogger"  : None} # name: plugin

        self.info_printer = InfoPrinter()

    def start_deauthentication_attack(self, plugins = []):
        if not self.air_deauthenticator.deauth_running:
            jamming_interface = self.configs["airdeauthor"]["jamming_interface"]
            if jamming_interface not in winterfaces():
                print "[-] jamming_interface '{}' does not exist".format(jamming_interface)
                return

            burst_count = 5
            targeted_only = False
            for arg in self.configs["airdeauthor"].keys():
                try:
                    val = self.configs["airdeauthor"][arg]
                    if arg == "burst_count":    burst_count = int(val)
                    else:                       targeted_only = True if val.lower() == "true" else False
                except ValueError:
                    print "[-] Burst count must be in integer form, not changing value."
                except KeyError:
                    pass
        
            self.air_deauthenticator.set_burst_count(int(burst_count))
            self.air_deauthenticator.set_targeted(targeted_only)
            self.air_deauthenticator.start_deauthentication_attack(jamming_interface)
        else:
            print "[-] Deauthentication attack still running"

    def start_access_point(self, plugins = []):
        '''
        This method is responsible for starting the access point with hostapd 
        while also avoiding conflicts with NetworkManager.
        It replaces the original NetworkManager.conf file
        and adding some lines that tell it to ignore managing the interface 
        that we are going to use as AP then it restarts the service
        '''

        # Start by getting all the info from the configuration file
        try:
            ap_interface = self.configs["airhost"]["ap_interface"]
            internet_interface = self.configs["airhost"]["internet_interface"]
            gateway = self.configs["airhost"]["dnsmasqhandler"]["gateway"]
            dhcp_range = self.configs["airhost"]["dnsmasqhandler"]["dhcp_range"]
            ssid = self.configs["airhost"]["aplauncher"]["ssid"]
            bssid = self.configs["airhost"]["aplauncher"]["bssid"]
            channel = self.configs["airhost"]["aplauncher"]["channel"]
            hw_mode = self.configs["airhost"]["aplauncher"]["hw_mode"]
            dns_servers = self.configs["airhost"]["dnsmasqhandler"]["dns_server"]
        except KeyError as e:
            print "[-] Unable to start Access Point, too few configurations"
            return False

        if  ap_interface not in winterfaces():
            print "[-] ap_interface '{}' does not exist".format(ap_interface)
            return False

        if internet_interface not in interfaces():
            print "[-] internet_interface '{}' does not exist".format(internet_interface)
            return False

        # NetworkManager setup
        if self.network_manager.set_mac_and_unmanage(ap_interface, bssid, retry = True):
            self.network_manager.iptables_redirect(ap_interface, internet_interface)
            self.network_manager.configure_interface(ap_interface, gateway)
            
            # dnsmasq and hostapd setup
            try:
                captive_portal_mode = self.configs["airhost"]["dnsmasqhandler"]["captive_portal_mode"].lower() == "true"
            except KeyError:
                captive_portal_mode = False

            self.air_host.dnsmasqhandler.set_captive_portal_mode(captive_portal_mode)
            self.air_host.dnsmasqhandler.write_dnsmasq_configurations(ap_interface, gateway, dhcp_range, dns_servers)
            try:
                self.air_host.aplauncher.write_hostapd_configurations(
                    interface=ap_interface, ssid=ssid, bssid=bssid, channel=channel, hw_mode=hw_mode,
                    encryption=self.configs["airhost"]["aplauncher"]["encryption"], 
                    auth=self.configs["airhost"]["aplauncher"]["auth"],
                    cipher=self.configs["airhost"]["aplauncher"]["cipher"],
                    password=self.configs["airhost"]["aplauncher"]["password"])
            except KeyError:
                self.air_host.aplauncher.write_hostapd_configurations(
                    interface=ap_interface, ssid=ssid, bssid=bssid, channel=channel, hw_mode=hw_mode)
            except Exception as e:
                print e
                return

            # Add plugins
            self.add_airhost_plugins(plugins)

            # Start services
            self.air_host.start_access_point(ap_interface)
            return True

        print dedent("""
                    [-] Errors occurred while trying to start access point, 
                    try restarting network services and unplug your network adapter""")
        return False

    def add_airhost_plugins(self, plugins):
        airhost_plugins = self.configs["airhost"]["plugins"]
        for plugin in plugins:
            if plugin == "dnsspoofer":
                dnsspoofer_plugin = airhost_plugins["dnsspoofer"]
                hosts_path = self.config_files["hosts_conf"]
                spoof_ip = self.configs["airhost"]["plugins"]["dnsspoofer"]["spoof_ip"]
                spoof_pages = self.configs["airhost"]["plugins"]["dnsspoofer"]["spoof_pages"]

                httpserver = None
                if dnsspoofer_plugin["httpserver"].lower() == "true":
                    apache_config_path = self.config_files["apache_conf"]
                    apache_root_path = self.config_files["apache_root"]
                    ssl = dnsspoofer_plugin["ssl_on"].lower() == "true"
                    overwrite = dnsspoofer_plugin["overwrite_pages"].lower() == "true"
                    httpserver = HTTPServer(apache_config_path, apache_root_path, ssl, overwrite)

                dnsspoofer = DNSSpoofer(spoof_ip, hosts_path, httpserver, spoof_pages)

                self.plugins["dnsspoofer"] = dnsspoofer
                self.air_host.add_plugin(dnsspoofer)
        
    def start_sniffer(self, plugins = []):
        # Sniffing options
        if not self.air_scanner.sniffer_running:
            self.add_airscanner_plugins(plugins)

            sniff_probes = self.configs["airscanner"]["probes"].lower() == "true"
            sniff_beacons = self.configs["airscanner"]["beacons"].lower() == "true"

            sniffing_interface = self.configs["airscanner"]["sniffing_interface"]
            if  sniffing_interface not in winterfaces():
                print "[-] sniffing_interface '{}' does not exist".format(sniffing_interface)
                return

            mac = self.configs["airhost"]["aplauncher"]["bssid"]

            if not self.network_manager.set_mac_and_unmanage(sniffing_interface, mac, retry = True):
                print "[-] Unable to set mac and unmanage, resetting interface and retrying."
                print "[-] Sniffer will probably crash."

            self.air_scanner.set_probe_sniffing(sniff_probes)
            self.air_scanner.set_beacon_sniffing(sniff_beacons)
            self.air_scanner.start_sniffer(sniffing_interface)
                
        else:
            print "[-] Sniffer already running"

    def add_airscanner_plugins(self, plugins):
        plugin_configs = self.configs["airscanner"]["plugins"]
        for plugin in plugins:
            if plugin == "packetlogger":
                packetlogger_configs = plugin_configs["packetlogger"]
                destination_folder = packetlogger_configs["destination_folder"]
                filter_list = packetlogger_configs["filters"]
                or_filter = packetlogger_configs["filter_mode"].lower() == "or"

                packetlogger = PacketLogger(destination_folder, filter_list, or_filter)

                self.plugins["packetlogger"] = packetlogger
                self.air_scanner.add_plugin(packetlogger)



    def stop_air_communications(self, stop_sniffer, stop_ap, stop_deauth):
        if stop_sniffer and self.air_scanner.sniffer_running:
            self.air_scanner.stop_sniffer()
            self.network_manager.cleanup_filehandler()

        if stop_ap and self.air_host.is_running():
            self.air_host.stop_access_point()
            self.air_host.cleanup()
            self.network_manager.cleanup()

        if stop_deauth and self.air_deauthenticator.deauth_running:
            self.air_deauthenticator.stop_deauthentication_attack()

    def service(self, service, option, plugins = []):
        if service == "airdeauthor":
            if option == "start":
                self.start_deauthentication_attack(plugins)
            else:
                self.stop_air_communications(False, False, True)
        elif service == "airhost":
            if option == "start":
                self.start_access_point(plugins)
            else:
                self.stop_air_communications(False, True, False)
        elif service == "airscanner":
            if option == "start":
                self.start_sniffer(plugins)
            else:
                self.stop_air_communications(True, False, False)


    # APLauncher action methods
    def airhost_copy_ap(self, id):
        password_info = dedent( """ 
                                Note:   The AP you want to copy uses encryption, 
                                        you have to specify the password in the airhost/aplauncher configurations.
                                """)
        bssid_info = dedent("""
                            Note:   Issues will arise when starting the 
                                    rogue access point with a bssid that exists nearby.
                            """)
        access_point = self.air_scanner.get_access_point(id)
        if access_point:
            self.configs["airhost"]["aplauncher"]["ssid"] = access_point.ssid
            self.configs["airhost"]["aplauncher"]["bssid"] = access_point.bssid
            self.configs["airhost"]["aplauncher"]["channel"] = access_point.channel

            self.configs["airhost"]["aplauncher"]["encryption"] = access_point.crypto
            self.configs["airhost"]["aplauncher"]["auth"] = access_point.auth
            self.configs["airhost"]["aplauncher"]["cipher"] = access_point.cipher

            if self.configs["airhost"]["aplauncher"]["encryption"].lower() != "opn":
                print password_info

            print bssid_info
            ConfigurationManager().config.write() # Singleton perks ;)
        else:
            print "[-] No access point with ID = {}".format(str(id))
        
    def airhost_copy_probe(self, id):
        probe = self.air_scanner.get_probe_request(index)
        if probe:
            if not probe.ap_ssid or probe.ap_ssid == "":
                print "[-] Probe request needs to specify SSID or it cannot be copied."
                return

            self.configs["airhost"]["aplauncher"]["ssid"] = probe.ap_ssid

            # TODO if it has bssid it's because the AP is listed in the AP list
            if probe.ap_bssids:
                self.configs["airhost"]["aplauncher"]["bssid"] = probe.ap_bssids[0]

            self.configs["airhost"]["aplauncher"]["encryption"] = "None"

            ConfigurationManager().config.write() # Singleton perks ;)
        else:
            print "[-] No probe with ID = {}".format(str(id))

    # Deauthor action methods
    def deauthor_add(self, add_type, filter_string):
        if add_type == "aps":
            add_list = ObjectFilter().filter(self.air_scanner.get_access_points(), filter_string)
            for ap in add_list:
                self.air_deauthenticator.add_ap(ap.bssid, ap.ssid)
        elif add_type == "clients":
            self.air_scanner.update_bssids_in_probes()
            add_list = ObjectFilter().filter(self.air_scanner.get_probe_requests(), filter_string)
            for client in add_list:
                client_mac = client.client_mac
                if len(client.ap_bssids) > 0:
                    for bssid in client.ap_bssids:
                        if bssid and bssid != "":
                            self.air_deauthenticator.add_client(client_mac, bssid, client.ap_ssid)
                else:
                    print "[-] Cannot add client '{}' because no AP bssid is associated".format(client_mac)
    

    def deauthor_del(self, del_type, filter_string):
        if del_type == "aps":
            del_list = set(ObjectFilter().filter(self.air_deauthenticator.aps_to_deauth, filter_string))
            self.air_deauthenticator.del_aps(del_list)
        elif del_type == "clients":
            del_list = ObjectFilter().filter(self.air_deauthenticator.clients_to_deauth, filter_string)
            self.air_deauthenticator.del_clients(del_list)


    # Informational print methods
    def print_sniffed_aps(self, filter_string = None):
        ap_list = self.air_scanner.get_access_points()
        ap_arg_list = [ "id","bssid","ssid","channel","rssi",
                        "crypto","cipher","auth"]
        headers = ["ID:", "BSSID:", "SSID:", "CHANNEL:", "SIGNAL:", "CRYPTO:", "CIPHER:", "AUTH:"]
        self.info_printer.add_info("sniffed_ap", ap_list, ap_arg_list, headers)
        self.info_printer.print_info("sniffed_ap", filter_string)

    def print_sniffed_probes(self, filter_string = None):
        self.air_scanner.update_bssids_in_probes()
        probe_list = self.air_scanner.get_probe_requests()
        probe_arg_list = ["id","client_mac","client_org","ap_ssid","ap_bssids","rssi","type"]
        headers = ["ID:", "CLIENT MAC:", "CLIENT ORG:", "AP SSID:", "AP BSSID:", "SIGNAL:", "TYPE:"]
        self.info_printer.add_info("sniffed_probe", probe_list, probe_arg_list, headers)
        self.info_printer.print_info("sniffed_probe", filter_string)

    def print_aps_to_deauth(self, filter_string = None):
        bssid_list = list(self.air_deauthenticator.aps_to_deauth)
        bssid_arg_list = ["id","bssid","ssid"]
        headers = ["ID:", "AP BSSID:", "AP SSID"]
        self.info_printer.add_info("deauth_bssid", bssid_list, bssid_arg_list, headers)
        self.info_printer.print_info("deauth_bssid", filter_string)

    def print_clients_to_deauth(self, filter_string = None):
        client_list = list(self.air_deauthenticator.clients_to_deauth)
        client_arg_list = ["id","client_mac","ap_bssid","ap_ssid"]
        headers = ["ID:", "CLIENT MAC:", "AP BSSID:", "AP SSID:"]
        self.info_printer.add_info("deauth_client", client_list, client_arg_list, headers)
        self.info_printer.print_info("deauth_client", filter_string)


    def print_connected_clients(self, filter_string = None):
        client_list = self.air_host.aplauncher.connected_clients
        client_arg_list = ["id","name","mac_address","ip_address","vendor","rx_packets","tx_packets","signal"]
        headers = ["ID:", "CLIENT NAME:", "CLIENT MAC:", "CLIENT IP:", "VENDOR:", "RX PACKETS:", "TX PACKETS:", "SIGNAL:"]
        self.info_printer.add_info("connected_client", client_list, client_arg_list, headers)
        self.info_printer.print_info("connected_client", filter_string)
