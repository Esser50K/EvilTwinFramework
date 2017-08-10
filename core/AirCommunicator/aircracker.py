import sys, os
from netaddr import EUI, OUI
from subprocess import call


class WPAHandshake(object):
    """
    Minimalistic representation of a WPA handshake
    Info is parsed from the file names and is enough to pass arguments
    to coWPAtty and HalfWPACracker
    """
    def __init__(self, id=0, ssid=None, client_mac=None, location=None):
        self.id = id
        self.ssid = ssid
        self.client_mac = client_mac
        self.location = location
        self.client_org = None
        try:
            self.client_org = EUI(self.client_mac).oui.registration().org   # OUI - Organizational Unique Identifier
        except: pass                                                        # OUI not registered exception

class WEPDataFile(object):

    def __init__(self, id=0, bssid=None, date=None, location=None):
        self.id = id
        self.bssid = bssid
        self.date = date
        self.location = location
        self.ap_org = None
        try:
            self.ap_org = EUI(self.bssid).oui.registration().org    # OUI - Organizational Unique Identifier
        except: pass    


class AirCracker(object):

    def __init__(self, wpa_cracker = None, log_dir = "data/"):
        self.wpa_handshakes         = []
        self.half_wpa_handshakes    = []
        self.wep_data_logs          = []
        self.wpa_cracker = wpa_cracker
        self.log_dir = log_dir
        self.load_wpa_handshakes()
        self.load_half_wpa_handshakes()

    def load_wpa_handshakes(self):
        del self.wpa_handshakes[:]
        for handshake in os.listdir(self.log_dir + "wpa_handshakes"):
            handshake = self._parse_filename_to_handshake(handshake, False)
            if handshake != None:
                self.wpa_handshakes.append(handshake)

    def load_half_wpa_handshakes(self):
        del self.half_wpa_handshakes[:]
        for handshake in os.listdir(self.log_dir + "wpa_half_handshakes"):
            handshake = self._parse_filename_to_handshake(handshake, True)
            if handshake != None:
                self.half_wpa_handshakes.append(handshake)

    def load_wep_data_logs(self):
        del self.wep_data_logs[:]
        for data_log in os.listdir(self.log_dir + "wep_captures"):
            data_log = self._parse_wep_data_filename(data_log)
            if data_log != None:
                self.wep_data_logs.append(data_log)

    def _parse_filename_to_handshake(self, handshake, is_half):
        try:
            handshake_name = handshake.split(".")[0]
            _, ssid, client_mac = handshake_name.split("_")
            return  WPAHandshake(len(self.half_wpa_handshakes), ssid, client_mac, os.path.abspath(self.log_dir + "wpa_half_handshakes/"+handshake)) if is_half else \
                    WPAHandshake(len(self.wpa_handshakes), ssid, client_mac, os.path.abspath(self.log_dir + "wpa_handshakes/"+handshake))
        except: pass

    def _parse_wep_data_filename(self, wepfile):
        try:
            filename = wepfile.split(".")[0]
            _, bssid, date = filename.split("_")
            return WEPDataFile(len(self.wep_data_logs), bssid, date, self.log_dir + "wep_captures/"+wepfile)
        except: 
            pass

    def set_wpa_cracker(self, wpa_cracker):
        self.wpa_cracker = wpa_cracker

    def prepare_wpa_cracker(self, id, is_half):
        handshake = self.half_wpa_handshakes[id] if is_half else self.wpa_handshakes[id]
        self.wpa_cracker.ssid = handshake.ssid
        self.wpa_cracker.pcap_file = handshake.location


    def launch_handshake_cracker(self, id, is_half, wpa_cracker = None):
        if not self.wpa_cracker and not wpa_cracker:
            print "[-] WPA Cracker not yet set."
            return

        if wpa_cracker:
            self.wpa_cracker = wpa_cracker

        try:
            id = int(id)
        except:
            print "[-] ID must be an integer"
            return

        self.load_wpa_handshakes()
        self.load_half_wpa_handshakes()

        if (is_half and (id > len(self.half_wpa_handshakes) or id < 0)) or (id > len(self.wpa_handshakes)):
            print "[-] Chosen index is out of bounds"
            return

        self.prepare_wpa_cracker(id, is_half)
        self.wpa_cracker.spawn_cracker()

    def launch_wep_cracker(self, id):
        self.load_wep_data_logs()

        if id < 0 or id > len(self.wep_data_logs)-1:
            print "[-] Chosen index is out of bounds"
            return

        execution_string = "aircrack-ng '{}'\n".format(self.wep_data_logs[id].location)
        with open("wep_rcfile.sh", "w") as rcfile:
            shebang = "#!/bin/sh\n"
            back_to_bash = "exec bash"
            rcfile.write(shebang + execution_string + back_to_bash)

        os.system("chmod +x wep_rcfile.sh")
        if execution_string != None:
            print "[+] Called:", execution_string
            call("sudo gnome-terminal -e".split() + [ "./wep_rcfile.sh" ])
        os.system("rm wep_rcfile.sh")




