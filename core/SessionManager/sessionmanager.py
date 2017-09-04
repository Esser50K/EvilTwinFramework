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
from reporter import Reporter
from session import Session
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

        def start_new_session(self):
            if self._session:
                self.save_session()

            self._date = strftime("%d_%m_%Y")
            if self._date not in os.listdir(self._sessions_folder):
                self._session_id = 1
                self._session_folder = self._sessions_folder + self._date + "/session1/"
                os.mkdir(self._sessions_folder + self._date)
                os.mkdir(self._session_folder)
            else:
                self._session_id = len(os.listdir(self._sessions_folder + self._date)) + 1
                self._session_folder = self._sessions_folder + self._date + "/session" + str(self._session_id) + "/"
                os.mkdir(self._session_folder)

            self._session = Session()  # Actually create new session

        def load_previous_session(self, date, id):
            self._session_folder = self._sessions_folder + date + "/session" + str(id) + "/"

            self._session = Session()
            self._session.read_events(self._session_folder)
            self._session.read_commands(self._session_folder)
            self._session.parse_session_data(self._session_folder)

        def save_session(self):
            self._session.save_session(self._session_folder)

        def log_command(self, command):
            self._session.append_command(command)
            self._command_reporter.write_log_line(command)

        def log_event(self, event, to_print = True):
            event_str = str(event)
            self._session.append_command(event_str)
            self._command_reporter.write_log_line(event_str)
            if to_print:
                print event_str

        def update_session_data(self, key, data):
            self._session.set_session_data(key, data)

        def session_prompt(self):
            self._date = strftime("%d_%m_%Y")
            if self._date in os.listdir(self._sessions_folder):
                answer = raw_input("[+] Found previous session. Do you want to load it? [y/n]:")
                if answer.lower() in ["y", "yes"]:
                    # Load previous session
                    print "[+] Loading last session from {}".format(strftime("%d/%m/%Y"))
                    id = len(os.listdir(self._sessions_folder + self._date))
                    self.load_previous_session(self._date, id)
                    self._initiate_reporters()
                    return

            # Create new session
            print "[+] Creating new session on {}".format(strftime("%d/%m/%Y"))
            self.start_new_session()
            self._initiate_reporters()

        def _initiate_reporters(self):
            self._command_reporter = Reporter(self._session_folder + self._session.commands_filename)
            self._event_reporter = Reporter(self._session_folder + self._session.events_filename)
            self._command_reporter.open()
            self._event_reporter.open()

        def get_session(self):
            return self._session

        def get_command_history(self):
            return self._session.command_history

        def close_session(self):
            self._command_reporter.close()
            self._event_reporter.close()

    def __init__(self):
        if not SessionManager.instance:
            SessionManager.instance = SessionManager.__SessionManager()

    def __getattr__(self, name):
        return getattr(self.instance, name)
