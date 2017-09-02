'''
This module contains the classes to represent
wireless interfaces as well as methods to handle them
and their information
'''

import os
import pyric.pyw as pyw
from utils import NetUtils, FileHandler
from subprocess import check_output
from textwrap import dedent

class NetworkCard(object):

    def __init__(self, interface):

        self.interface = interface
        self.card = None
	self.modes = None
        self.original_mac = None
	self._ap_mode_support = None
        self._monitor_mode_support = None

        try:
            self.card = pyw.getcard(interface)
	    self.modes = pyw.devmodes(self.card)
	    self.original_mac = pyw.macget(self.card)

	    # Important capabilities
            self._ap_mode_support = "AP" in self.modes
            self._monitor_mode_support = "monitor" in self.modes
        except: pass
        
        self._number_of_supported_aps = None
        self._is_managed = False

    def _valid_card(self):
        return self.card is not None

    def set_managed(self, state):
        self._is_managed = state

    def is_managed(self):
        return self._is_managed

    def set_txpower(self, dbm):
        if self._verify_card():
            pyw.txset(self.card, 'fixed', dbm)

    def get_txpower(self):
        if self._verify_card():
            return pyw.txget(self.card)

    def set_mode(self, mode):
        try:
            pyw.down(self.card)
            pyw.modeset(self.card, mode)
            pyw.up(self.card)
        except Exception as e:
            print e, "\n[-] Unable to set mode on {}".format(self.interface)
            return False

    def get_mode(self):
        try:
            return pyw.modeget(self.card)
        except Exception:
            return None

    def set_mac(self, mac):
        try:
            pyw.down(self.card)
            pyw.macset(self.card, mac)
            pyw.up(self.card)
            return True
        except Exception as e:
            print e, "\n[-] Unable to set mac on {}".format(self.interface)
            return False

    def get_mac(self):
        try:
            return pyw.macget(self.card)
        except:
            return None

    def ifconfig(self, ip, netmask=None, broadcast=None):
        if self._valid_card():
            pyw.up(self.card)
            pyw.ifaddrset(self.card, ip, netmask, broadcast)

    def get_ip(self):
        try:
            return pyw.ifaddrget(self.card)[0]
        except:
            return None

    def get_subnet(self):
        ip_split = self.get_ip().split('.')
        netmask_split = self.get_mask().split('.')
        subnet = [0, 0, 0, 0]
        for i in range(4):
            subnet[i] = ip_split[i] if netmask_split[i] != "0" else "0"

        return ".".join(subnet)

    def get_mask(self):
        try:
            return pyw.ifaddrget(self.card)[1]
        except:
            return None

    def get_bcast(self):
        try:
            return pyw.ifaddrget(self.card)[2]
        except:
            return None

    def get_channel(self):
        try:
            return pyw.chget(self.card)
        except:
            return None

    def set_channel(self, channel):
        try:
            pyw.chset(self.card, channel)
        except:
            return None

    def get_available_channels(self):
        try:
            return pyw.devchs(self.card)
        except:
            return None

    def get_phy_index(self):
        try:
            return self.card.phy
        except:
            return None

    def set_mtu_size(self, nbytes):
        os.system('ifconfig {interface} mtu {size}'.format( interface=self.interface,
                                                            size=nbytes))

    def get_connected_clients(self):
        try:
            mode = pyw.modeget(self.card)
        except:
            mode = None

        if mode == 'AP':
            os.system("iw dev {} station dump".format(self.interface))
        else:
            print "[-] '{}' is not on AP mode".format(self.interface)

    def get_number_of_supported_aps(self):
        if self._ap_mode_support and not self._number_of_supported_aps:
            iw_out = check_output("iw list".split()).split("\n")
            found_phy, found_combinations = False, False
            for line in iw_out:
                if not found_phy:
                    if "phy{}".format(self.card.phy) in line:
                        found_phy = True
                elif not found_combinations:
                    if "valid interface combinations:" in line:
                        found_combinations = True
                else:
                    if "{ AP, mesh point }" in line:
                        try:
                            number_string = line.split("=")[-1].strip()
                            real_num = ""
                            for  char in number_string:
                                if not char.isdigit():
                                    break
                                real_num += char

                            self._number_of_supported_aps = int(real_num)
                            break
                        except:
                            print "Error converting '{}' to int".format(line.split("=")[-1].strip())
                            return None

        return self._number_of_supported_aps

    def is_virtual(self):
        return "_" in self.interface


class NetworkManager(object):

    def __init__(self, networkmanager_config_path='/etc/NetworkManager/NetworkManager.conf', unmanaged_interfaces = []):
        self.interfaces = pyw.interfaces()
        self.netcards = { interface: NetworkCard(interface) for interface in pyw.winterfaces() }
        self.nm_config_file = networkmanager_config_path
        self.file_handler = None

        self.unmanaged_interfaces_setup(unmanaged_interfaces)

    def unmanaged_check(self, interface):
        ok_status = ["unmanaged", "disconnected", "unavailable"]
        for line in check_output(["nmcli", "dev"]).split("\n"):
            try:
                args = line.split()[:4]
                iface, type, status, connection = args
                if interface == iface:
                    return status in ok_status
                else: continue
            except: pass

        return True

    def unmanaged_interfaces_setup(self, unmanaged_interfaces):
        for iface in unmanaged_interfaces:
            if iface in self.interfaces:
                self.set_mac_and_unmanage(iface, self.netcards[iface].get_mac(), True)

    def iptables_redirect(self, from_if, to_if):
        card = self.get_netcard(from_if)  # Get NetCard object
        if card is not None:
            NetUtils().accept_forwarding(from_if)
            if not card.is_virtual():
                NetUtils().set_postrouting_interface(to_if)
                NetUtils().add_routing_rule(card.get_subnet(), card.get_mask(), card.get_ip())

    def configure_interface(self, interface, ip, netmask=None, broadcast=None, mtu=1800):
        NetUtils().interface_config(interface, ip, netmask, broadcast)
        NetUtils().set_interface_mtu(interface, mtu)

    def set_mac_and_unmanage(self, interface, mac, retry = False, virtInterfaces = 0):
        card = self.get_netcard(interface)

        # Runs at least once, if retry is flagged
        # it will try to reset the interface and repeat the process
        while(True):
            if card is not None:
                if not card.set_mac(mac):
                    return False

                if not self.unmanaged_check(interface):
                    if not self.network_manager_ignore(interface, mac, virtInterfaces):
                        return False

                    os.system("service network-manager restart")  # Restarting NetworkManager service

                if pyw.macget(card.card) == mac:
                    return True

            if not retry:
                break

            print "[-] Unable to set mac and unmanage, resetting interface and retrying."
            retry = False
            try:
                card = NetworkCard(interface)
                if card.get_mode() != 'managed':
                    card.set_mode('managed')
            except:
                return False

        return False

    # NetworkManager is usually a conflicting process,
    # but we can configure it to ignore the interface
    # we use as access point or to sniff packets
    def network_manager_ignore(self, interface, mac_address, virtInterfaces = 0):
        if virtInterfaces > 0:
            mac_address = mac_address[:-1] + "0"
        interface_ignore_string = interface

        for i in range(virtInterfaces):
            interface_ignore_string += ",mac:{}".format(mac_address[:-1] + str(i + 1))
            interface_ignore_string += ",interface-name:{}_{}".format(interface, i)

        try:
            ignore_config = dedent( """
                                    [main]
                                    plugins=ifupdown,keyfile

                                    [ifupdown]
                                    managed=false

                                    [keyfile]
                                    unmanaged-devices=mac:{mac_address},interface-name:{ignore_interfaces}
                                    """.format( mac_address=mac_address,
                                                ignore_interfaces=interface_ignore_string
                                                ))

            self.cleanup_filehandler()
            self.file_handler = FileHandler(self.nm_config_file)
            self.file_handler.write(ignore_config)
            self.netcards[interface].set_managed(True)
        except Exception as e:
            print e
            return False

        return True

    def get_netcard(self, interface):
        netcard = None
        try:
            try:
                netcard = self.netcards[interface]
            except KeyError:
                # Check if it was plugged in at runtime
                self.netcards = { interface: NetworkCard(interface) for interface in pyw.winterfaces() }
                netcard = self.netcards[interface]
        except KeyError:
            print "[-] Interface: '{}' does not exist".format(interface)
            return None

        return netcard

    def cleanup_filehandler(self):
        if self.file_handler:
            self.file_handler.restore_file()
            self.file_handler = None
            os.system("service network-manager restart")

    def reset_interfaces(self):
        restart_services = False
        for card in [card for card in self.netcards if not self.netcards[card].is_virtual]:
            self.netcards[card].set_mac(self.netcards[card].original_mac)
            self.netcards[card].set_mode('managed')
            if self.netcards[card].is_managed():
                restart_services = True

        if restart_services:
            os.system("service networking restart")
            os.system("service network-manager restart")

    def cleanup(self):
        NetUtils().flush_iptables()
        self.cleanup_filehandler()
        self.reset_interfaces()
