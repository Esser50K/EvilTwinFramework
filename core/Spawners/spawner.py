"""
This is the Spawner mother class.

All man in the middle tools should 
that can be spawned should have their 
own class which must be a subclass of Spawner.
"""

import os
from subprocess import Popen
from etfexceptions import InvalidFilePathException

class Spawner(object):

	def __init__(self, config):
		self.calling = None
		self.name = None
		self.process = None
		self.is_set_up = False
		self.config = config
		self.arg_string = " ".join(config["args"])
		self.system_location = config["system_location"]

		if not os.path.exists(self.system_location):
			raise InvalidFilePathException("The path '{location}' does not exist, \
											'{name}' could not be loaded.".format(	location=system_location,
																					name=name))

	# This method is supposed to be overriden by subclass
	def setup_process(self):
		self.is_set_up = True

	# This method is supposed to be overriden by subclass
	def restore_process(self):
		os.system("pkill {}".format(self.name))
		self.is_set_up = False


	def spawn(self):
		self.setup_process()
		self.process = Popen("sudo gnome-terminal -e".split() +
							 ['{name} {args}'.format(	name=self.name,
														args=self.arg_string)])

		print "[+] Spawned '{}' with args:\n{}".format(self.calling, self.arg_string)
		print "[/] NOTE: Remember to restore '{}' after closing window.".format(self.name)