import os
from AuxiliaryModules.packetfilter import BSSIDPacketFilter, SSIDPacketFilter, ChannelPacketFilter
from AuxiliaryModules.events import NeutralEvent
from SessionManager.sessionmanager import SessionManager
from plugin import AirScannerPlugin
from scapy.utils import PcapWriter

class PacketLogger(AirScannerPlugin):

    def __init__(self, config):
        super(PacketLogger, self).__init__(config, "packetlogger")
        self.destination_folder = self.config["destination_folder"]
        self._nlogs = self._get_log_count()
        self.packet_filters = []
        filter_list = self.config["filters"]
        self.filter_types = {
                                "bssid" : BSSIDPacketFilter,
                                "ssid" : SSIDPacketFilter,
                                "channel" : ChannelPacketFilter
                            }
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
        try:
            filter = self.filter_types[filter_type](value)
        except KeyError:
            print "There is no filter definition for '{}'.".format(filter_type)
        except:
            pass

        if filter:
            self.packet_filters.append(filter)

    def refresh(self):
        self._nlogs = self._get_log_count()
        self.packet_logger = PcapWriter(self.destination_folder + "packet_log{n}.cap".format(n = self._nlogs),
        append=True, sync=True)

    def log(self, packet, OR = False):
        if(OR):
            # Only needs to pass through 1 filter
            for filter in self.packet_filters:
                if filter.passes(packet):
                    self.packet_logger.write(packet)
                    return
        else:
            # Needs to pass through all filter
            for filter in self.packet_filters:
                if not filter.passes(packet):
                    return
            self.packet_logger.write(packet)

    def handle_packet(self, packet):
        self.log(packet, self.or_filter)
