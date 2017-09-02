"""
Comlete RadioTap from scapy-com. New Scapy version missing a couple of good updates.
"""
from scapy.packet import *
from scapy.fields import *
from scapy.layers.dot11 import PrismHeader, Dot11

class RadioTapField(Field):
    """Field implementing addfield,getfield shared by other RadioTap Fields"""
    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return Field.addfield(self, pkt, s, val)
        else:
            return s

    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return Field.getfield(self, pkt, s)
        else:
            return s, None

class RadioTapByteField(ByteField):
    """One byte field, share functionality across other one byte RadioTapFields"""
    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return ByteField.addfield(self, pkt, s, val)
        else:
            return s

    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return ByteField.getfield(self, pkt, s)
        else:
            return s, None


class RadioTapTSFTField(RadioTapField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "8s")

    def is_applicable(self, pkt):
        '''Returns True if Field is present according to RadioTap.present field,
        existence of pkt.present must be checked - otherwise won't read pcaps properly'''
        # first part of condition required by RadioTap.get_decoded_length
        if (pkt.present is not None) and (pkt.present & 0x1 == 0x1):
            return 1
        return 0

    def i2h(self, pkt, x):
        if (x is None) or (pkt.present is None):
            return 0
        return struct.unpack('Q', x)[0]


class RadioTapFlagsField(RadioTapByteField):
    def is_applicable(self, pkt):
        if (pkt.present is not None) and ( pkt.present & 0x2 == 0x2 ):
            return 1
        return 0


class RadioTapRateField(RadioTapByteField):
    def is_applicable(self, pkt):
        if (pkt.present is not None) and ( pkt.present & 0x4 == 0x4 ):
            return 1
        return 0

    def i2h(self, pkt, x):
        if ( x is None ) or ( pkt.present is None ):
            return 0
        return "%s Mbps" % (0.5 * x)  # RadioTap Rate unit is 500 Kbps


class RadioTapPadBeforeChannelField(RadioTapByteField):
    def is_applicable(self, pkt):
        if (pkt.present is not None) and not ( pkt.present & 0x4 == 0x4 ):
            return 1
        return 0


class RadioTapChannelField(RadioTapField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "4s")

    def is_applicable(self, pkt):
        if ( pkt.present is not None ) and ( pkt.present & 0x8 == 0x8 ):
                return 1
        return 0

    def i2h(self, pkt, x):
        if ( x is None ) or ( pkt.present is None ):
            return 0
        return int("%02x%02x" %  (ord(x[1]), ord(x[0])), 16)


class RadioTapFHSSField(RadioTapField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "2s")

    def is_applicable(self, pkt):
        if ( pkt.present is not None ) and ( pkt.present & 0x10 == 0x10 ):
            return 1
        return 0


class RadioTapAntennaSignalField(SignedByteField):
    def is_applicable(self, pkt):
        if ( pkt.present is not None ) and ( pkt.present & 0x20 == 0x20 ):
            return 1
        return 0

    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return SignedByteField.addfield(self, pkt, s, val)
        else:
            return s

    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return SignedByteField.getfield(self, pkt, s)
        else:
            return s, None


class RadioTapAntennaNoiseField(SignedByteField):
    def is_applicable(self, pkt):
        if ( pkt.present is not None ) and ( pkt.present & 0x40 == 0x40 ):
            return 1
        return 0

    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return SignedByteField.addfield(self, pkt, s, val)
        else:
            return s

    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return SignedByteField.getfield(self, pkt, s)
        else:
            return s, None


class RadioTapLockQualityField(RadioTapField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "2s")

    def is_applicable(self, pkt):
        if ( pkt.present is not None ) and ( pkt.present & 0x80 == 0x80 ):
            return 1
        return 0


class RadioTap(Packet):
    name = "RadioTap dummy"
    fields_desc = [ ByteField('version', 0),
                    ByteField('pad', 0),
                    FieldLenField('len', None, 'notdecoded', '<H', adjust=lambda pkt, x: x + 8),
                    FlagsField('present', None, -32, ['TSFT', 'Flags', 'Rate', 'PadChannel', 'Channel',
                                                      'FHSS', 'dBm_AntSignal', 'dBm_AntNoise', 'Lock_Quality',
                                                      'TX_Attenuation', 'dB_TX_Attenuation', 'dBm_TX_Power', 'Antenna',
                                                      'dB_AntSignal', 'dB_AntNoise', 'RX_Flags', '',
                                                      '', '', 'XChannel', 'MCS',
                                                      '', '', '', '',
                                                      '', '', '', '',
                                                      '', 'Radiotap_Namespace', 'Vendor_Namespace', 'Ext']),
                    RadioTapTSFTField('TSFT', 0),
                    RadioTapFlagsField('Flags', 0),
                    RadioTapRateField('Rate', 0),
                    RadioTapPadBeforeChannelField('PadChannel', 0),
                    RadioTapChannelField('Channel', 0),
                    RadioTapFHSSField('FHSS', 0),
                    RadioTapAntennaSignalField('dBm_AntSignal', 0),
                    RadioTapAntennaNoiseField('dBm_AntNoise', 0),
                    RadioTapLockQualityField('Lock_Quality', 0),
                    StrLenField('notdecoded', "", length_from= lambda pkt:pkt.len - pkt.get_decoded_length()) ]

bind_layers( PrismHeader,   Dot11,         )
bind_layers( RadioTap,      Dot11,         )
