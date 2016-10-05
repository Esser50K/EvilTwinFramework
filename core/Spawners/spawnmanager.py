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

class SpawnManager(object):

	def __init__(self):
		self.spawners = []

	def add_spawner(self, spawner_name, system_location, arg_string):
		try:
			spawner = None
			if spawner_name == "mitmf":
				spawner = MITMFSpawner(system_location)
			elif spawner_name == "beef":
				spawner = BeefSpawner(system_location)
			elif spawner_name == "sslstrip":
				spawner = SSLStripSpawner(system_location)
			elif spawner_name == "ettercap":
				spawner = EttercapSpawner(system_location)

			if spawner:
				spawner.set_arg_string(arg_string)
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
