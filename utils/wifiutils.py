# -*- coding: utf-8 -*-
"""
This module simply has the Wi-Fi AP and client classes defined
"""
from AuxiliaryModules.packet import get_vendor

class AccessPoint(object):
    """
    This class represents an Access Point Object
    Most arguments can be filled out automatically with a scan
    The wpa/wpa2 key has to be specified
    """

    def __init__(self,  id = 0, ssid=None, bssid=None, channel=None, rssi=None,
                        encryption_methods=(), encryption_cipher=None, authentication_method=None):
        self.id = id
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.rssi = rssi
        self.crypto = "/".join(encryption_methods)
        self.cipher = encryption_cipher
        self.auth = authentication_method
        self.psk = None 

    def __str__(self):
        return  " ".join(   [   str(self.bssid), str(self.ssid), \
                                str(self.crypto), str(self.cipher), str(self.auth)    ]   )

    def __eq__(self, other):
        return self.bssid == other.bssid

    def __hash__(self):
        return hash(self.bssid + self.ssid)


# TODO: Add new constructor that receives info directly
class WiFiClient(object):
    """
    This class represents a WiFi Client
    These are detected whenever they send probe send probe requests
    One can check if they are associated if the Access Point has responded
    """

    def __init__(self,  id = 0, client_mac = None,
                        associated_bssid = None, associated_ssid = None,
                        rssi = None, probeInfo = None):
        self.id = id
        self.client_mac = client_mac
        self.client_org = get_vendor(client_mac) if client_mac else None
        self.rssi = rssi
        self.associated_ssid = associated_ssid
        self.associated_bssid = associated_bssid

        # Could have only passed probeInfo and other fields None
        self.probed_ssids = set()
        self._parse_probe(probeInfo)

    def is_associated(self):
        return self.associated_ssid is not None

    def _parse_probe(self, probeInfo):
        if probeInfo is not None:
            self.client_mac = probeInfo.client_mac
            self.client_org = probeInfo.client_org
            self.probed_ssids = set([probeInfo.ap_ssid])
            if probeInfo.type == "REQ":
                self.rssi = probeInfo.rssi
            elif probeInfo.type == "ASSO":
                self.associated_ssid = probeInfo.ap_ssid
                self.associated_bssid = probeInfo.ap_bssids[0] # If its association response there is only 1 bssid

    def __eq__(self, other):
        return self.client_mac == other.client_mac

    def __hash__(self):
        return hash(self.client_mac)

class ProbeInfo(object):

    def __init__(self,  id = 0,
                        client_mac = None, client_org = None, 
                        ap_ssid = None, ap_bssids = [], 
                        rssi = None, ptype = None):
        self.id = id
        self.client_mac = client_mac
        self.client_org = client_org
        self.ap_bssids = ap_bssids
        self.ap_ssid = ap_ssid
        self.rssi = rssi
        self.type = ptype # REQ, RESP, ASSO 

    def isPair(self, otherProbe):
        return  (self.client_mac == other.client_mac) and \
                (self.ap_ssid == other.ap_ssid) and \
                (self.type != other.type)

    def __eq__(self, other):
        return  (self.client_mac == other.client_mac) and \
                (self.ap_ssid == other.ap_ssid) and \
                (self.type == other.type)

    def __str__(self):
        return "{}-{}-{}".format(self.client_mac, self.ap_ssid, self.type)