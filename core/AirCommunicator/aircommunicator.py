# -*- coding: utf-8 -*-
'''
This is a wrapper class responsible for
everything that concerns air communications
such as setting up the access point as well
as sniffing the packets in the air
'''

from pyric.pyw import interfaces, winterfaces
from aplauncher import APLauncher
from airscanner import AirScanner
from airdeauthor import AirDeauthenticator
from ConfigurationManager.configmanager import ConfigurationManager
from utils.networkmanager import NetworkManager, NetworkCard
from prettytable import PrettyTable
from textwrap import dedent
from threading import Thread

class AirCommunicator(object):

    def __init__(self):
        self.configs = ConfigurationManager().config["etf"]["aircommunicator"]
        config_locations = ConfigurationManager().config["etf"]["config_location"]
        self.ap_launcher = APLauncher(config_locations["dnsmasq_conf"], config_locations["hostapd_conf"])
        self.air_scanner = AirScanner()
        self.air_deauthenticator = AirDeauthenticator()
        self.network_manager = NetworkManager(config_locations["networkmanager_conf"])

    def start_deauthentication_attack(self):
        if not self.air_deauthenticator.deauth_running:
            jamming_interface = self.configs["airdeauthor"]["jamming_interface"]
            if  jamming_interface not in winterfaces():
                print "[-] jamming_interface '{}' does not exist".format(jamming_interface)
                return

            burst_count = 5
            targeted_only = False
            for arg in self.configs["airdeauthor"].keys():
                try:
                    val = self.configs["airdeauthor"][arg]
                    if arg == "burst_count":    burst_count = int(val)
                    else:                       targeted_only = True if val.lower() == "true" else False
                except KeyError:
                    pass
        
            self.air_deauthenticator.set_burst_count(int(burst_count))
            self.air_deauthenticator.set_targeted(targeted_only)
            self.air_deauthenticator.start_deauthentication_attack(jamming_interface)
        else:
            print "[-] Deauthentication attack still running"

    def start_access_point(self):
        '''
        This method is responsible for starting the access point with hostapd 
        while also avoiding conflicts with NetworkManager.
        It replaces the original NetworkManager.conf file
        and adding some lines that tell it to ignore managing the interface 
        that we are going to use as AP then it restarts the service
        '''

        # Start by getting all the info from the configuration file
        try:
            ap_interface = self.configs["aplauncher"]["ap_interface"]
            internet_interface = self.configs["aplauncher"]["internet_interface"]
            gateway = self.configs["aplauncher"]["dnsmasq"]["gateway"]
            dhcp_range = self.configs["aplauncher"]["dnsmasq"]["dhcp_range"]
            ssid = self.configs["aplauncher"]["hostapd"]["ssid"]
            bssid = self.configs["aplauncher"]["hostapd"]["bssid"]
            channel = self.configs["aplauncher"]["hostapd"]["channel"]
            hw_mode = self.configs["aplauncher"]["hostapd"]["hw_mode"]

            dns_servers = self.configs["aplauncher"]["dnsmasq"]["dns_server"]
            if type(dns_servers) is not list:
                dns_servers = [dns_servers]
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
            self.ap_launcher.write_dnsmasq_configurations(ap_interface, gateway, dhcp_range, dns_servers)
            try:
                self.ap_launcher.write_hostapd_configurations(
                    interface=ap_interface, ssid=ssid, bssid=bssid, channel=channel, hw_mode=hw_mode,
                    encryption=self.configs["aplauncher"]["hostapd"]["encryption"], 
                    auth=self.configs["aplauncher"]["hostapd"]["auth"],
                    cipher=self.configs["aplauncher"]["hostapd"]["cipher"],
                    password=self.configs["aplauncher"]["hostapd"]["password"])
            except KeyError:
                self.ap_launcher.write_hostapd_configurations(
                    interface=ap_interface, ssid=ssid, bssid=bssid, channel=channel, hw_mode=hw_mode)
            except Exception as e:
                print e
                return

            # Start services
            self.ap_launcher.start_access_point(ap_interface)
            return True

        print dedent("""
                    [-] Errors occurred while trying to start access point, 
                    try restarting network services and unplug your network adapter""")
        return False
        
    def start_sniffer(self):
        # Sniffing options
        if not self.air_scanner.sniffer_running:
            sniff_probes = self.configs["airscanner"]["probes"].lower() == "true"
            sniff_beacons = self.configs["airscanner"]["beacons"].lower() == "true"

            sniffing_interface = self.configs["airscanner"]["sniffing_interface"]
            if  sniffing_interface not in winterfaces():
                print "[-] sniffing_interface '{}' does not exist".format(sniffing_interface)
                return

            mac = self.configs["aplauncher"]["hostapd"]["bssid"]

            if not self.network_manager.set_mac_and_unmanage(sniffing_interface, mac, retry = True):
                print "[-] Unable to set mac and unmanage, resetting interface and retrying."
                print "[-] Sniffer will probably crash."

            self.air_scanner.set_probe_sniffing(sniff_probes)
            self.air_scanner.set_beacon_sniffing(sniff_beacons)
            self.air_scanner.start_sniffer(sniffing_interface)
                
        else:
            print "[-] Sniffer already running"

    def stop_air_communications(self, stop_sniffer, stop_ap, stop_deauth):
        if stop_sniffer and self.air_scanner.sniffer_running:
            self.air_scanner.stop_sniffer()
            self.network_manager.cleanup_filehandler()

        if stop_ap and self.ap_launcher.ap_running:
            self.ap_launcher.stop_access_point()
            self.ap_launcher.restore_config_files()
            self.network_manager.cleanup()

        if stop_deauth and self.air_deauthenticator.deauth_running:
            self.air_deauthenticator.stop_deauthentication_attack()

    def service(self, service, option):
        if service == "deauthor":
            if option == "start":
                self.start_deauthentication_attack()
            else:
                self.stop_air_communications(False, False, True)
        elif service == "aplauncher":
            if option == "start":
                self.start_access_point()
            else:
                self.stop_air_communications(False, True, False)
        elif service == "sniffer":
            if option == "start":
                self.start_sniffer()
            else:
                self.stop_air_communications(True, False, False)



    # APLauncher action methods
    def aplauncher_copy_ap(self, index):
        password_info = dedent( """ 
                                Note:   The AP you want to copy uses encryption, 
                                        you have to specify the password in the aplauncher configurations.
                                """)
        bssid_info = dedent("""
                            Note:   When starting the rogue access point 
                                    with a bssid that already nearby issues will arise.
                            """)
        try:
            access_point = self.air_scanner.get_access_points()[index]
            self.configs["aplauncher"]["hostapd"]["ssid"] = access_point.ssid
            self.configs["aplauncher"]["hostapd"]["bssid"] = access_point.bssid
            self.configs["aplauncher"]["hostapd"]["channel"] = access_point.channel

            self.configs["aplauncher"]["hostapd"]["encryption"] =   "wpa/wpa2" if   "wpa" in access_point.encryption_methods and    \
                                                                                    "wpa2" in access_point.encryption_methods       \
                                                                    else "wpa2" if "wpa2" in access_point.encryption_methods        \
                                                                    else "wpa" if "wpa" in access_point.encryption_methods          \
                                                                    else "wep" if "wep" in access_point.encryption_methods          \
                                                                    else "None"
            self.configs["aplauncher"]["hostapd"]["auth"] = access_point.authentication_method
            self.configs["aplauncher"]["hostapd"]["cipher"] = access_point.encyption_cypher

            if self.configs["aplauncher"]["hostapd"]["encryption"] != "None":
                print password_info

            print bssid_info
            ConfigurationManager().config.write() # Singleton perks ;)
        except IndexError as e:
            print e, "\n[-] Specified index '{}' is out of bounds".format(str(index))

    def aplauncher_copy_probe(self, index):
        try:
            probe = self.air_scanner.get_probe_requests()[index]

            if not probe.ap_ssid or probe.ap_ssid == "":
                print "[-] Probe request needs to specify SSID or it cannot be copied."
                return

            self.configs["aplauncher"]["hostapd"]["ssid"] = probe.ap_ssid

            # TODO if it has bssid it's because the AP is listed in the AP list
            if probe.ap_bssids:
                self.configs["aplauncher"]["hostapd"]["bssid"] = probe.ap_bssids[0]

            self.configs["aplauncher"]["hostapd"]["encryption"] = "None"

            ConfigurationManager().config.write() # Singleton perks ;)
        except IndexError as e:
            print e, "\n[-] Specified index '{}' is out of bounds".format(str(index))

    # Deauthor action methods
    def deauthor_flush(self):
        del self.air_deauthenticator.bssids_to_deauth[:]
        self.air_deauthenticator.clients_to_deauth.clear()

    def deauthor_add(self, add_type, index):
        try:
            if add_type == "bssid":
                self.air_deauthenticator.add_bssid(self.air_scanner.get_access_points()[index].bssid)
            elif add_type == "client":
                self.air_scanner.update_bssid_in_probes()
                client = self.air_scanner.get_probe_requests()[index]
                client_mac = client.client_mac
                print client.ap_bssids
                if len(client.ap_bssids) > 0:
                    for bssid in client.ap_bssids:
                        if bssid and bssid != "":
                            self.air_deauthenticator.add_client(client_mac, bssid)
                else:
                    print "[-] Cannot add client '{}' because no AP bssid is associated".format(client_mac)
        except IndexError as e:
            print e, "\n[-] Specified index '{}' is out of bounds".format(str(index))


    def deauthor_del(self, del_type, index):
        try:
            if del_type == "bssid":
                del self.air_deauthenticator.bssids_to_deauth[index]
            elif del_type == "client":
                client_mac = self.air_deauthenticator.clients_to_deauth.keys()[index]
                del self.air_deauthenticator.clients_to_deauth[client_mac]
        except IndexError as e:
            print e, "\n[-] Specified index '{}' is out of bounds".format(str(index))


    # Informational print methods
    def print_sniffed_aps(self):
        ap_list = self.air_scanner.get_access_points()
        ap_arg_list = [ [   str(ap.bssid), 
                            str(ap.ssid), 
                            str(ap.channel),
                            str(ap.rssi),
                            "/".join(ap.encryption_methods), 
                            str(ap.encyption_cypher),
                            str(ap.authentication_method)] for ap in ap_list]

        table = PrettyTable(["ID:", "BSSID:", "SSID:", "CHANNEL:", "SIGNAL:", "CRYPTO:", "CIPHER:", "AUTH:"])
        i = 0
        for ap in ap_arg_list:
            table.add_row([str(i)] + ap)
            i += 1

        print unicode(str(table), errors='ignore')

    def print_sniffed_probes(self):
        self.air_scanner.update_bssid_in_probes()
        probe_arg_list = []

        for probe in self.air_scanner.get_probe_requests():
            probe_arg_list.append([ probe.client_mac, probe.client_org, 
                                    probe.ap_ssid, "\n".join(probe.ap_bssid), 
                                    probe.rssi, probe.type ])

        table = PrettyTable(["ID:", "CLIENT MAC:", "CLIENT ORG:", "AP SSID:", "AP BSSID:", "SIGNAL:", "TYPE:"])
        i = 0
        for probe in probe_arg_list:
            table.add_row([str(i)] + probe)
            i += 1

        print unicode(str(table), errors='ignore')

    def print_bssids_to_deauth(self):
        bssid_list = self.air_deauthenticator.bssids_to_deauth
        bssid_arg_list = []
        for bssid in bssid_list:
            ap_ssid = self.air_scanner.get_ssid_from_bssid(bssid)
            bssid_arg_list.append([bssid, ap_ssid])

        table = PrettyTable(["ID:", "AP BSSID:", "AP SSID"])

        i = 0
        for bssid in bssid_arg_list:
            table.add_row([str(i)] + bssid)
            i += 1

        print unicode(str(table), errors='ignore')

    def print_clients_to_deauth(self):
        client_list = self.air_deauthenticator.clients_to_deauth.keys()
        client_arg_list = []
        for cmac in client_list:
            ap_bssid = self.air_deauthenticator.clients_to_deauth[cmac]
            ap_ssid = self.air_scanner.get_ssid_from_bssid(ap_bssid[0])
            client_arg_list.append([cmac, "\n".join(ap_bssid), ap_ssid])

        table = PrettyTable(["ID:", "CLIENT MAC:", "AP BSSID:", "AP SSID:"])

        i = 0
        for client in client_arg_list:
            table.add_row([str(i)] + client)
            i += 1

        print unicode(str(table), errors='ignore')

    def print_connected_clients(self):
        client_list = self.ap_launcher.connected_clients.keys()
        client_arg_list = []
        for cmac in client_list:
            client = self.ap_launcher.connected_clients[cmac]
            client_arg_list.append([client.name, cmac, 
                                    client.ip_address, client.vendor, 
                                    client.rx_packets, client.tx_packets, client.signal])

        table = PrettyTable(["ID:", "CLIENT NAME:", "CLIENT MAC:", "CLIENT IP:", "VENDOR:", "RX PACKETS:", "TX PACKETS:", "SIGNAL:"])

        i = 0
        for client in client_arg_list:
            table.add_row([str(i)] + client)
            i += 1

        print unicode(str(table), errors='ignore')
