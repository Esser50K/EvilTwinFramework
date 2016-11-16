import os
from plugin import AirHostPlugin
from subprocess import Popen

class CredentialPrinter(AirHostPlugin):

	def __init__(self, log_folder, log_file_name):
		super(CredentialPrinter, self).__init__()
		self.log_folder = log_folder
		self.log_file_name = log_file_name
		self.credential_printer_process = None

	def start(self):
		hash_log_file = "{folder}{name}{id}.log".format(folder = self.log_folder,
														name = self.log_file_name,
														id = len(os.listdir("data/hashes/")))
		open(hash_log_file, "w").close()
		self.credential_printer_process = Popen(("tail -F " + hash_log_file).split())

	def restore(self):
		self.credential_printer_process.send_signal(9)
