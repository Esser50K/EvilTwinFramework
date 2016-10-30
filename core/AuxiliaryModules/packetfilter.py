import os
from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt

class PacketFilter(object):

	def __init__(self, packet):
		self.packet = packet

	def passes(self):
		pass

class BSSIDPacketFilter(PacketFilter):

	def __init__(self, bssid):
		super(SSIDPacketFilter, self).__init__(packet)
		self.bssid = bssid

	def passes(self, packet):
		if Dot11Beacon in packet or Dot11ProbeResp in self.packet:
			bssid = packet[Dot11].addr3		
			return self.bssid == bssid
		else:
			return False

class SSIDPacketFilter(PacketFilter):

	def __init__(self, ssid):
		super(SSIDPacketFilter, self).__init__(packet)
		self.ssid = ssid

	def passes(self, packet):
		if Dot11Beacon in packet or Dot11ProbeResp in self.packet:
			elt_layer = self.packet[Dot11Elt]
			while isinstance(elt_layer, Dot11Elt):
				if elt_layer.ID == 0:
					ssid = elt_layer.info
					return self.ssid == ssid

				elt_layer = elt_layer.payload
		else:
			return False

class ChannelPacketFilter(PacketFilter):

	def __init__(self, channel):
		super(SSIDPacketFilter, self).__init__(packet)
		self.channel = channel

	def passes(self, packet):
		if Dot11Beacon in packet or Dot11ProbeResp in self.packet:
			elt_layer = self.packet[Dot11Elt]
			while isinstance(elt_layer, Dot11Elt):
				if elt_layer.ID == 3:
					try:
						channel = ord(elt_layer.info)
					except Exception:
						channel = str(elt_layer.info)
						
					return str(channel) == str(self.channel)

				elt_layer = elt_layer.payload
		else:
			return False


