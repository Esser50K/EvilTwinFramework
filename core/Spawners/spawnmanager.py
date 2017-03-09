"""
This class will save all used Spawners
and manage them by checking if the tool is present in the system
and setting up and restoring them
"""

import os
from etfexceptions import InvalidFilePathException
from spawner import Spawner
from mitmfspawner import MITMFSpawner
from beefspawner import BeefSpawner
from sslstripspawner import SSLStripSpawner
from ettercapspawner import EttercapSpawner
from ConfigurationManager.configmanager import ConfigurationManager

class SpawnManager(object):

	def __init__(self):
		self.spawners = []
		self.configs = ConfigurationManager().config["etf"]["spawner"]

	def add_spawner(self, spawner_name):
		try:
			spawner = None
			for spawner in Spawner.__subclasses__():
				spawner_instance = spawner()
				if spawner_instance.name == spawner_name:
					spawner_instance.spawn()
					self.spawners.append(spawner_instance)

		except InvalidFilePathException as e:
			print e

	def restore_spawner(self, spawner_name):
		for spawner in self.spawners:
			if spawner.name == spawner_name:
				spawner.restore_process()
				del spawner
				return True

		print "[-] Spawner with name '{}' was not called yet.".format(spawner_name)
		return False

	def restore_all(self):
		for spawner in self.spawners:
			spawner.restore_process()
			del spawner
