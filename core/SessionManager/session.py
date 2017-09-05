"""
This class represents a pentesting session.
"""
from os.path import exists
from threading import Lock
from events import parse_event_line
from jsonpickle import encode, decode

class Session(object):

    def __init__(self, date = "", id = 0, name = ""):
        self.date = date
        self.id = id
        self.name = name
        self.path = date + "/session" + str(id) + "_" + name + "/"
        self.event_lock, self.command_lock, self.data_lock = Lock(), Lock(), Lock()
        self.event_history      = []
        self.command_history    = []
        self.session_data = {
                                "sniffed_aps"       : {},
                                "sniffed_clients"   : {},
                                "sniffed_probes"    : [],
                                "ap_targets"        : set(),
                                "client_targets"    : set()
                            }
        self.commands_filename = "commands.log"
        self.events_filename = "events.log"
        self.index = 0

    def set_index(self, index):
        self.index = index

    def append_event(self, event):
        with self.event_lock:
            self.event_history.append(event)

    def append_command(self, command):
        with self.command_lock:
            self.command_history.append(command)

    def set_session_data(self, key, data):
        if key not in self.session_data.keys():
            print "[-] Wrong key '{}': will not save this data."
            return

        with self.data_lock:
            self.session_data[key] = data

    def read_events(self, folder_path):
        file_path = folder_path + self.events_filename
        if not exists(file_path):
            return

        with open(file_path, "r") as log_file:
            for line in log_file:
                event = parse_event_line(line)
                if event is not None:
                    self.append_event(event)

    def read_commands(self, folder_path):
        file_path = folder_path + self.commands_filename
        if not exists(file_path):
            return

        with open(file_path, "r") as log_file:
            for line in log_file:
                self.append_command(line)

    def parse_session_data(self, folder_path):
        for key in self.session_data.keys():
            filename = key + ".data"
            path = folder_path + "/" + filename
            if not exists(path):
                continue

            try:
                with open(path, "r") as data_file:
                    self.session_data[key] = decode(data_file.read())
            except ValueError:
                continue  # Error decoding just means the file is empty...
            except Exception as e:
                print e
                print "[-] Error trying to decode '{}' data from '{}'.".format(key, path)

    def save_session(self, folder_path):
        for key in self.session_data.keys():
            filename = key + ".data"
            path = folder_path + filename
            try:
                with open(path, "w") as data_file:
                    data_file.write(encode(self.session_data[key]))
            except Exception as e:
                print e
                print "[-] Error trying to write '{}' data to '{}'.".format(key, path)
