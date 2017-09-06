"""
This is another Singleton Class used for managing pentesting sessions.

The class holds information about the current session such as:
- Command History
- Event History
- Session Data (info stored in AirScanner and AirInjector classes)

The class will also be able to log events that will result in a report file.
This is very useful for professional pentesters as they can look back at a report of previous sessions.
"""
import os
from AuxiliaryModules.infoprinter import InfoPrinter
from reporter import Reporter
from session import Session
from shutil import rmtree
from time import strftime

class SessionManager(object):
    instance = None

    class __SessionManager(object):
        def __init__(self, sessions_folder="core/SessionManager/sessions/"):
            self._event_reporter = None
            self._command_reporter = None
            self._date = None
            self._session_id = -1
            self._session = None
            self._sessions_folder = sessions_folder  # Folder with all session folders
            self._session_folder = None              # Specific folder of current session
            self._is_temporary = False
            self._session_list = []

            self.info_printer = InfoPrinter()

        def start_new_session(self, name):
            if self._session:
                self.close_session()

            self._is_temporary = True
            self._session_name = name
            self._date = strftime("%d_%m_%Y")
            if self._date not in os.listdir(self._sessions_folder):
                self._session_id = 1
                self._session = Session(self._date, self._session_id, self._session_name)
                self._session_folder = self._sessions_folder + self._session.path
                os.mkdir(self._sessions_folder + self._date)
                os.mkdir(self._session_folder)
            else:
                self._session_id = len(os.listdir(self._sessions_folder + self._date)) + 1
                self._session = Session(self._date, self._session_id, self._session_name)
                self._session_folder = self._sessions_folder + self._session.path
                os.mkdir(self._session_folder)

            self._initiate_reporters()

        def _load_previous_session(self, date, id):
            self._session_name = self._get_session_name(date, id)
            print "[+] Loading session '{}'!".format(self._session_name)
            self._session = Session(date, id, self._session_name)
            self._load_info_from_current_session()

        def load_session(self, index):
            if index >= len(self._session_list):
                print "[-] Session index out of bounds!"
                return

            if self._is_temporary:
                self._cleanup_tmp_session()
            self._session = self._session_list[index]
            self._load_info_from_current_session()

        def _load_info_from_current_session(self):
            self._session_folder = self._sessions_folder + self._session.path
            self._session.read_events(self._session_folder)
            self._session.read_commands(self._session_folder)
            self._session.parse_session_data(self._session_folder)
            self._is_temporary = False
            self._initiate_reporters()

        def _get_session_name(self, date, id):
            for session in os.listdir(self._sessions_folder + date):
                if session.startswith("session" + str(id)):
                    return "_".join(session.split("_")[1:])
            return None

        def get_current_session_name(self):
            return self._session_name

        def get_current_session_path(self):
            return self._session.path

        def save_session(self):
            self._is_temporary = False
            self._session.save_session(self._session_folder)

        def log_command(self, command):
            self._session.append_command(command)
            self._command_reporter.write_log_line(command)

        def log_event(self, event, to_print = False):
            event_str = str(event)
            self._session.append_command(event_str)
            self._event_reporter.write_log_line(event_str)
            if to_print:
                print event_str

        def update_session_data(self, key, data):
            self._session.set_session_data(key, data)

        def session_prompt(self):
            self._date = strftime("%d_%m_%Y")
            if self._date in os.listdir(self._sessions_folder) and \
               len(os.listdir(self._sessions_folder + "/" + self._date)) > 0:
                # Load previous session
                print "[+] Found previous session from today. Loading it."
                print "[+] Loading last session from {}".format(strftime("%d/%m/%Y"))
                self._session_id = len(os.listdir(self._sessions_folder + self._date))
                self._load_previous_session(self._date, self._session_id)
                return

            self._load_all_sessions()
            if len(self._session_list) == 0:
                print "[-] No previous sessions to load. Creating new One."
                answer = "n"
            else:
                answer = raw_input("[+] Do you want to load an older session? [Y/n]: ")

            if answer.lower() in "yes" or answer == "":
                self.print_sessions()
                while True:
                    try:
                        answer = int(raw_input("[+] Choose a session by index: "))
                        if answer >= len(self._session_list):
                            print "[-] Index out of bounds."
                            continue
                        break
                    except:
                        print "[-] Index must be Integer!"
                self._session = self._session_list[answer]
                self._load_previous_session(self._session.date, self._session.id)
                return

            # Create new session
            print "[+] Creating new temporary session on {}".format(strftime("%d/%m/%Y"))
            self.start_new_session("_".join(raw_input("[+] Enter the desired session name: ").split()))

        def _initiate_reporters(self):
            self._command_reporter = Reporter(self._session_folder + self._session.commands_filename)
            self._event_reporter = Reporter(self._session_folder + self._session.events_filename)

        def get_session(self):
            return self._session

        def get_command_history(self):
            return self._session.command_history

        def _cleanup_tmp_session(self):
            rmtree(self._session_folder)

        def close_session(self):
            self._command_reporter.close()
            self._event_reporter.close()

            if self._is_temporary:
                self._cleanup_tmp_session()
            else:
                self.save_session()

        def _load_all_sessions(self):
            self._session_list = [
                                    Session(datefolder, int(session.split("_")[0][-1]), "_".join(session.split("_")[1:]))
                                    for datefolder in os.listdir(self._sessions_folder) if os.path.isdir(self._sessions_folder + "/" + datefolder)
                                    for session in os.listdir(self._sessions_folder + "/" + datefolder)
                                 ]

        def get_all_sessions(self):
            self._load_all_sessions()
            all_sessions = []
            index = 0
            for session in self._session_list:
                session.set_index(index)
                all_sessions.append(session)
                index += 1

            return all_sessions

        def print_sessions(self, filter_string = None):
            info_key = "sessions"
            sessions = self.get_all_sessions()
            session_args = ["index", "date", "id", "name"]
            session_headers = ["INDEX:", "DATE:", "ID:", "NAME:"]
            self.info_printer.add_info(info_key, sessions, session_args, session_headers)
            self.info_printer.print_info(info_key, filter_string)

    def __init__(self):
        if not SessionManager.instance:
            SessionManager.instance = SessionManager.__SessionManager()

    def __getattr__(self, name):
        return getattr(self.instance, name)
