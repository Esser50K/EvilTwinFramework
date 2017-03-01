"""
This class will save all used Spawners
and manage them by checking if the tool is present in the system
and setting up and restoring them
"""

import os
from etfexceptions import InvalidFilePathException
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
			if spawner_name in map(lambda x: x.name, self.spawners):
				for spawned in self.spawners:
					if spawned.name == spawner_name:
						spawner = spawned
			elif spawner_name == "mitmf":
				spawner = MITMFSpawner(self.configs[spawner_name])
			elif spawner_name == "beef":
				spawner = BeefSpawner(self.configs[spawner_name])
			elif spawner_name == "sslstrip":
				spawner = SSLStripSpawner(self.configs[spawner_name])
			elif spawner_name == "ettercap":
				spawner = EttercapSpawner(self.configs[spawner_name])

			if spawner:
				spawner.spawn()
				self.spawners.append(spawner)

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
