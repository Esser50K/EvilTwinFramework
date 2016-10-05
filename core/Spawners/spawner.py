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

	def __init__(self, system_location):
		self.system_location = system_location
		self.calling = None
		self.name = None
		self.arg_string = None
		self.process = None

		if not os.path.exists(system_location):
			raise InvalidFilePathException("The path '{location}' does not exist, \
											'{name}' could not be loaded.".format(	location=system_location,
																					name=name))

	def set_arg_string(self, string):
		self.arg_string = string

	# This method is supposed to be overriden by subclass
	def setup_process(self):
		pass

	# This method is supposed to be overriden by subclass
	def restore_process(self):
		pass

	def spawn(self):
		self.setup_process()
		self.process = Popen("sudo gnome-terminal -e".split() +
							 ['{name} {args}'.format(	name=self.name,
														args=self.arg_string)])

		print "[+] Spawned '{}' with args:\n{}".format(self.calling, self.arg_string)
		print "[/] NOTE: Remember to restore '{}' after closing window.".format(self.name)