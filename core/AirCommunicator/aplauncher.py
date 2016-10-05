'''
This module is responsible for lauching the access point.
It makes use of hostapd and dnsmasq to provide an access point
and dhcp and dns services
'''

import os
import pyric.pyw as pyw
from netaddr import EUI, OUI
from etfexceptions import InvalidConfigurationException, MissingConfigurationFileException
from subprocess import Popen, check_output
from time import sleep
from textwrap import dedent
from threading import Thread
from utils.utils import FileHandler, NetUtils, DEVNULL

# TODO: makes sense to refactor this so the class actually holds the interface that it is running on, like the airscanner and deauthor
class APLauncher(object):

    def __init__(self, dnsmasq_config_path, hostapd_config_path):
        # Mandatory configuration files to start the access point successfully
        if (dnsmasq_config_path == None or hostapd_config_path == None) :
            raise MissingConfigurationFileException("dnsmasq and hostapd configuration files must be specified\n \
                                                    either by argument in the command line or in the etf.conf file")

        # State variables
        self.dnsmasq_running = False
        self.ap_running = False

        # Data variables
        self.dnsmasq_config_path = dnsmasq_config_path
        self.hostapd_config_path = hostapd_config_path
        self.connected_clients = {}

        # Extra processes/threads
        self.ap_process = None
        self.connected_clients_updator = None

        # List of configuration file handlers
        self.file_handlers = []

    # TODO the dhcp-range needs to be dynamic and loaded from ConfigManager
    def write_dnsmasq_configurations(self, interface, ip_gw, dhcp_range=[], nameservers=[]):
        configurations = dedent("""
                                interface={interface}
                                dhcp-range={dhcp_start}, {dhcp_end}, 12h
                                dhcp-option=3,{ip_gw}
                                dhcp-option=6,{ip_gw}
                                """.format( interface=interface,
                                            ip_gw=ip_gw,
                                            dhcp_start=dhcp_range[0],
                                            dhcp_end=dhcp_range[1]))
        for server in nameservers:
            configurations += "server={server}\n".format(server=server)

        try: # Look for dnsmasq file config handler
            file_handler = None
            for fhandler in self.file_handlers:
                if fhandler.current_file == self.dnsmasq_config_path:
                    file_handler = fhandler

            if not file_handler:
                file_handler = FileHandler(self.dnsmasq_config_path)
            file_handler.write(configurations)
            self.file_handlers.append(file_handler)
        except Exception as e:
            print e
            return False

        return True


    # TODO: Add support for multiple SSIDs! 
    def write_hostapd_configurations(self,  interface="wlan0", 
                                            ssid=None, 
                                            bssid=None, 
                                            channel="1", 
                                            hw_mode="g", 
                                            encryption=None, 
                                            auth="PSK", 
                                            cipher="CCMP", 
                                            password=None):

        try:
            file_handler = None
            for fhandler in self.file_handlers:
                if fhandler.current_file == self.hostapd_config_path:
                    file_handler = fhandler

            if not file_handler:
                file_handler = FileHandler(self.hostapd_config_path, backup=False)
            self.file_handlers.append(file_handler)
        except Exception as e:
            print e
            return False

        configurations = dedent("""
                                interface={interface}
                                ssid={ssid}
                                driver=nl80211
                                channel={channel}
                                hw_mode={hw_mode}
                                ignore_broadcast_ssid=0
                                """.format( interface=interface,
                                            ssid=ssid,
                                            channel=channel,
                                            hw_mode=hw_mode))

        # Spoof bssid from other access points
        if bssid:
            configurations += "bssid={bssid}\n".format(bssid=bssid)

        # May even want to mirror the encryption type and key 
        # so hosts can automatically connect if it is a known network
        if encryption:
            if ("wpa" in encryption):
                if password is None: 
                    raise InvalidConfigurationException("Must specify a password when choosing wpa or wpa2 encryption!\n")
                if len(password) < 8: 
                    raise InvalidConfigurationException("Specified password must have at least 8 printable digits\n")

                wpa_int = 1   

                # Check if input is 'wpa/wpa2'
                if "/" in encryption:
                    encryption = encryption.split("/")
                    # wpa=1 -> wpa, wpa=2 -> wpa2, wpa=3 -> wpa/wpa2
                    if "wpa2" in encryption:
                        wpa_int += 1
                    if "wpa" in encryption and "wpa2" in encryption:
                        wpa_int += 1
                elif encryption == "wpa2":
                    wpa_int += 1

                configurations += "wpa={wpa_int}\n".format(wpa_int=wpa_int)                 # configure wpa or wpa2
                configurations += "wpa_passphrase={password}\n".format(password=password)   # password minimum is 8 digits
                configurations += "wpa_key_mgmt=WPA-{auth}\n".format(auth=auth)             # authentication method: PSK or EAP
                configurations += "wpa_pairwise={cipher}\n".format(cipher=cipher)           # cipher: CCMP or TKIP

            elif encryption == "wep":
                if not (len(password) == 5 or len(password) == 13 or len(password) == 16):
                    raise InvalidConfigurationException("Specified must have 5 or 13 or 16 digits for WEP\n")

                configurations += "wep_default_key=0\n"
                configurations += "wep_key0=\"{key}\"".format(key=password)


        file_handler.write(configurations)
        return True

    def start_access_point(self, interface):
        print "[+] Killing already started processes and restarting network services"
        self.stop_access_point() # Restarting services helps avoiding some conflicts with dnsmasq

        print "[+] Starting hostapd background process"
        self.ap_process = Popen("hostapd {config_path}".format( config_path=self.hostapd_config_path).split(), 
                                stdout=DEVNULL,
                                stderr=DEVNULL)

        print "[+] Starting dnsmasq service"
        if not self.start_service("dnsmasq"):
            print "[-] Error starting dnsmasq, aborting AP launch"
            return

        self.dnsmasq_running = True
        self.ap_running = True
        self.connected_clients_updator = Thread(target=self.update_connected_clients, args=(interface, ))
        self.connected_clients_updator.start()

        print "[+] Access Point launched successfully"
        return True

    def stop_access_point(self):
        if self.ap_process != None:
            print "[+] Killing hostapd background process"
            self.ap_process.send_signal(9)  # Send SIGINT to process running hostapd
            self.ap_process = None

        print "[+] Stopping dnsmasq and hostapd services"
        self.stop_service("dnsmasq")
        self.stop_service("hostapd")
        os.system('pkill hostapd')      # Cleanup
        os.system('pkill dnsmasq')      # Cleanup
        self.ap_running = False
        self.dnsmasq_running = False
        if self.connected_clients_updator != None:
            self.connected_clients_updator.join()
            self.connected_clients_updator = None

        print "[+] Access Point stopped, restarting network services..."
        os.system('service networking restart')
        os.system('service NetworkManager restart')


    def start_service(self, service):
        return os.system('service {} restart'.format(service)) == 0 # Returns true if the operation was successful

    def stop_service(self, service):
        return os.system('service {} stop'.format(service)) == 0

    def restore_config_files(self):
        for fhandler in self.file_handlers:
            fhandler.restore_file()
        del self.file_handlers[:] # empty the file handler list


    def update_connected_clients(self, interface):
        while self.ap_running:
            self._parse_connected_clients(interface)
            sleep(3)

    def _parse_connected_clients(self, interface):
        try:
            if not pyw.modeget(pyw.getcard(interface)) == 'AP':
                print "[-] '{}' is not on AP mode".format(interface)
                return
        except Exception:
            return

        client_dump = check_output("iw dev {} station dump".format(interface).split()).split('Station')
        client_dump = [ map(str.strip, client.split("\n")) for client in client_dump if interface in client ]

        # At this point a client is a list of arguments to be parsed
        for client in client_dump:
            client_mac                  = client[0].split()[0].strip()
            client_name, client_ip      = self._get_ip_from_mac(interface, client_mac)
            inactivity_time             = client[1].split(":")[1].strip()
            rx_packets                  = client[3].split(":")[1].strip()
            tx_packets                  = client[5].split(":")[1].strip()
            signal                      = client[8].split(":")[1].strip()
            tx_bitrate                  = client[10].split(":")[1].strip()
            rx_bitrate                  = client[11].split(":")[1].strip()

            client = Client(client_name, client_mac, client_ip, inactivity_time, 
                            rx_packets, tx_packets, rx_bitrate, tx_bitrate, signal)

            if client_mac not in self.connected_clients:
                print "[+] New connected client with -> ip: {ip}, mac: {mac} ({vendor})".format(ip=client_ip, 
                                                                                                mac=client_mac, 
                                                                                                vendor=client.vendor)

            self.connected_clients[client_mac] = client # Overriding entry means update

    def _get_ip_from_mac(self, interface, mac):
        arp_output = check_output("arp -a -i {}".format(interface).split()).split("\n")
        for line in arp_output:
            if mac.lower() in line.lower():
                try:
                    device_name, device_ip = map(str.strip, (line.split()[0:2]))
                    device_ip = device_ip[1:-1] # Cut the enclosing parenthesis off: (0.0.0.0) -> 0.0.0.0
                    return (device_name, device_ip)
                except Exception as e:
                    print e
                    print "[-] Problem occurred while parsing arp output."

        return (None, None)



class Client(object):

    def __init__(self,  name, mac_address, ip_address, inactivity_time, 
                        rx_packets, tx_packets,
                        rx_bitrate, tx_bitrate,
                        signal):

        self.name = name
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.inactivity_time = inactivity_time
        self.rx_packets = rx_packets
        self.tx_packets = tx_packets
        self.tx_bitrate = tx_bitrate
        self.rx_bitrate = rx_bitrate
        self.signal = signal
        self.vendor = None
        try:
            self.vendor = EUI(mac_address).oui.registration().org      # OUI - Organizational Unique Identifier
        except Exception as e:
            pass

    def __str__(self):
        pass