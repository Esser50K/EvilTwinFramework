import os
from AuxiliaryModules.packetfilter import BSSIDPacketFilter, SSIDPacketFilter, ChannelPacketFilter
from AuxiliaryModules.events import NeutralEvent
from SessionManager.sessionmanager import SessionManager
from plugin import AirScannerPlugin
from scapy.utils import PcapWriter

class PacketLogger(AirScannerPlugin):

    def __init__(self):
        super(PacketLogger, self).__init__("packetlogger")
        self.destination_folder = self.config["destination_folder"]
        self._nlogs = self._get_log_count()
        self.packet_filters = []
        filter_list = self.config["filters"]
        for filter in filter_list:
            try:
                type, value = map(str.strip, filter.split("="))
                self.add_filter(type, value)
            except Exception as e:
                print e
                pass

        self.or_filter = self.config["filter_mode"].lower() == "or"
        self.current_log_file = "packet_log{n}.cap".format(n = self._nlogs)
        self.packet_logger = None

    def pre_scanning(self):
        self.packet_logger = PcapWriter(self.destination_folder + self.current_log_file,
                                        append=True, sync=True)
        SessionManager().log_event(NeutralEvent("Packet Logger initiated."))

    def _get_log_count(self):
        # Get the number of existing log files
        if os.path.exists(self.destination_folder):
            return len(filter(lambda x: x.startswith("packet_log"), os.listdir(self.destination_folder)))
        else:
            os.mkdir(self.destination_folder)
            return 0

    def add_filter(self, filter_type, value):
        filter = None
        if filter_type == "bssid":
            filter = BSSIDPacketFilter(value)
        elif filter_type == "ssid":
            filter = SSIDPacketFilter(value)
        elif filter_type == "channel":
            filter = ChannelPacketFilter(value)

        if filter:
            self.packet_filters.append(filter)

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
        self.packet_logger = PcapWriter(self.destination_folder + "packet_log{n}.cap".format(n = self._nlogs),
                                        append=True, sync=True)

    def handle_packet(self, packet):
        self.log(packet, self.or_filter)
