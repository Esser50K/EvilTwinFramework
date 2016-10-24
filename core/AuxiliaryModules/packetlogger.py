import os
from scapy.utils import PcapWriter

class PacketLogger(object):

	def __init__(self):
		self._nlogs = self._get_log_count()
		self.packet_filters = []
		self.current_log_file = "packet_log{n}.cap".format(n = self._nlogs)
		self.packet_logger = PcapWriter("data/captures/{log_file}".format(log_file = self.current_log_file), 
										append=True, sync=True)

	def _get_log_count(self):
		# Get the number of log existing log files
		if os.path.exists("data/captures/"):
			return len(filter(lambda x: x.startswith("packet_log"), os.listdir("data/captures/")))
		else:
			os.mkdirs("data/captures/")
			return 0

	def add_filter(self, filter):
		self.filter.append(filter)

	def log(self, packet, OR = False):
		# Only needs to pass through 1 filter
		if(OR):
			for filter in self.packet_filters:
				if filter.passes(packet):
					self.packet_logger.write(packet)
					return
		# Needs to pass through all filter
		else:
			for filter in self.packet_filters:
				if not filter.passes(packet):
					return

			self.packet_logger.write(packet)

	def refresh(self):
		self._nlogs = self._get_log_count()
		self.packet_logger = PcapWriter("data/captures/packet_log{n}.cap".format(n = self._nlogs), 
										append=True, sync=True)