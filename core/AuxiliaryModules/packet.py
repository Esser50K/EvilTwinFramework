
from netaddr import EUI, OUI
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, EAPOL

cipher_suites = { 'GROUP'   : '\x00\x0f\xac\x00',
                  'WEP'     : '\x00\x0f\xac\x01',
                  'TKIP'    : '\x00\x0f\xac\x02',
                  'CCMP'    : '\x00\x0f\xac\x04',
                  'WEP'     : '\x00\x0f\xac\x05' }

auth_suites = { 'MGT' : '\x00\x0f\xac\x01',
                'PSK' : '\x00\x0f\xac\x02' }

def get_vendor(mac):
        if mac != "":
            maco = EUI(mac)                         # EUI - Extended Unique Identifier
            try:
                return maco.oui.registration().org  # OUI - Organizational Unique Identifier
            except Exception as e:                  # OUI not registered exception
                return None
        return None

class Packet(object):

    def __init__(self, packet):
        self.packet = packet
        self.rssi = self._get_rssi_from_packet(packet)
        self.parse_packet()

    def parse_packet(self):
        pass

    def _get_rssi_from_packet(self, packet):
        try:
            return str(packet.dBm_AntSignal) + " dbm"
        except Exception as e:
            return None

    def _get_ssid_from_packet(self, packet):
        ssid = None
        if packet.haslayer(Dot11Elt):
            elt_layer = packet[Dot11Elt]

            while isinstance(elt_layer, Dot11Elt):
                if elt_layer.ID == 0:
                    ssid = elt_layer.info
                    break
                elt_layer = elt_layer.payload  # Check for more Dot11Elt packets within

        return ssid


class ClientPacket(Packet):
    def __init__(self, packet):
        self.client_mac = packet[Dot11].addr3
        if self.client_mac.lower() == "ff:ff:ff:ff:ff:ff":
            self.client_mac = packet[Dot11].addr2
        self.bssid = packet[Dot11].addr1
        self.ssid = self._get_ssid_from_packet(packet)
        self.client_vendor = get_vendor(self.client_mac)
        super(ClientPacket, self).__init__(packet)


class AccessPointPacket(Packet):
    def __init__(self, packet):
        self.ssid = self._get_ssid_from_packet(packet)
        self.bssid = packet[Dot11].addr3
        if self.bssid.lower() == "ff:ff:ff:ff:ff:ff":
            self.bssid = packet[Dot11].addr2
        self.client_mac = packet[Dot11].addr1
        self.client_vendor = get_vendor(self.client_mac)
        super(AccessPointPacket, self).__init__(packet)


class Beacon(AccessPointPacket):

    def __init__(self, packet):
        self.bssid = None
        self.channel = None
        self.encryption = None
        self.cipher = None
        self.auth = None
        super(Beacon, self).__init__(packet)

    def parse_packet(self):
        # Based on an answer from stack-overflow:
        # https://stackoverflow.com/questions/21613091/how-to-use-scapy-to-determine-wireless-encryption-type
        elt_layer = self.packet[Dot11Elt]

        cap = self.packet.sprintf(  "{Dot11Beacon:%Dot11Beacon.cap%}"
                                    "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
        rsn_info = None
        crypto = set()
        while isinstance(elt_layer, Dot11Elt):
            if elt_layer.ID == 3:
                try:
                    self.channel = str(ord(elt_layer.info))
                except Exception:
                    self.channel = str(elt_layer.info)
            elif elt_layer.ID == 48:
                crypto.add("WPA2")
                rsn_info = elt_layer.info
            elif elt_layer.ID == 221 and elt_layer.info.startswith('\x00P\xf2\x01\x01\x00'):
                crypto.add("WPA")
            elt_layer = elt_layer.payload # Check for more Dot11Elt packets within
        if not crypto:
            if 'privacy' in cap:
                crypto.add("WEP")
            else:
                crypto.add("OPN")

        # TODO: parse rsn_info corectly
        """
        if rsn_info:
            print self.ssid
            print ''.join( [ "%02X " % ord( x ) for x in rsn_info ] ).strip()
        """
        self.encryption = crypto
        if rsn_info or crypto:
            self.cipher, self.auth = self.find_auth_and_cipher(rsn_info, crypto)

    # TODO: Could be better and actually parse the packet instead of searching for byte sequences within
    def find_auth_and_cipher(self, info, crypto_methods):
        cipher_suite = None
        auth_suite = None

        if crypto_methods:
            crypto_methods = map(str.lower, crypto_methods)

        # Figure out cipher suite
        if info:
            crypto_methods = map(str.lower, crypto_methods)
            if ("wpa2" in crypto_methods or "wpa" in crypto_methods) and cipher_suites['CCMP'] in info:
                cipher_suite = 'CCMP'
            elif "wep" in crypto_methods:
                cipher_suite = 'WEP'

        if cipher_suite is None and ("wpa" in crypto_methods):
            cipher_suite = 'TKIP'

        # Figure out authentication method
        if info:
            if auth_suites['MGT'] in info:
                auth_suite = 'EAP'
            elif auth_suites['PSK'] in info:
                auth_suite = 'PSK'
        else:
            auth_suite = 'OPN'


        return (cipher_suite, auth_suite)


class ProbeResponse(AccessPointPacket):
    def __init__(self, packet):
        super(ProbeResponse, self).__init__(packet)

class ProbeRequest(ClientPacket):
    def __init__(self, packet):
        super(ProbeRequest, self).__init__(packet)

class AuthenticationResponse(AccessPointPacket):
    def __init__(self, packet):
        super(AuthenticationResponse, self).__init__(packet)

class AssociationResponse(AccessPointPacket):
    def __init__(self, packet):
        super(AssociationResponse, self).__init__(packet)
