"""
For some cases Scapy's sniff is just to slow. tcpdump as a background process is much more efficient.
"""
from scapy.all import rdpcap, Dot11WEP
from subprocess import Popen
from threading import Lock
from utils.utils import DEVNULL


class TCPDumpLogger(object):

    def __init__(self, interface, log_path, filter = None):
        self.interface = interface
        self.log_path = log_path
        self.filter = filter
        self.tcpdump_process = None
        self.is_logging = False
        self.log_lock = Lock()

    def is_logging(self):
        return self.is_logging

    def start_logging(self):
        tcpdump_string = "tcpdump -i {}".format(self.interface).split()
        tcpdump_string += [ self.filter ] if self.filter is not None else ""
        tcpdump_string += "-w {log}".format(log = self.log_path).split()

        self.tcpdump_process = Popen(tcpdump_string, stdout = DEVNULL, stderr = DEVNULL)
        with self.log_lock:
            self.is_logging = True

    def stop_logging(self):
        with self.log_lock:
            self.is_logging = False
            if self.tcpdump_process is not None:
                print "[+] Killing tcpdump background process"
                self.tcpdump_process.send_signal(9)  # Send SIGINT to process running tcpdum
                self.tcpdump_process = None

    def get_wep_data_count(self):
        wep_packets = None
        try:
            wep_packets = rdpcap(self.log_path)
        except Exception as e:
            print "[-] Error reading pcap file:", str(e)
            return
        n_data_packets = 0
        for p in wep_packets:
            if Dot11WEP in p:
                if p.iv is not None and p.iv != '':
                    n_data_packets += 1

        return n_data_packets
