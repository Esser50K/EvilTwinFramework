"""
This is another Singleton Class used for logging of relevant events.

This is very useful for professional pentesters as they can look back at a report of their last session.
"""
from threading import Lock

class Reporter(object):

    def __init__(self, file_path):
        self._lock = Lock()
        self.file_path = file_path
        self.log_file = None

    def is_open(self):
        return not self.log_file.closed

    def open(self):
        with self._lock:
            self.log_file = open(self.file_path, "a")

    def close(self):
        with self._lock:
            if self.log_file:
                self.log_file.close()

    def write_log_line(self, line):
        with self._lock:
            if self.is_open():
                self.log_file.write(line + "\n")
            else:
                print "is closed."
