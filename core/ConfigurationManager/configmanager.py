"""
This class is responsible for reading, writing, updating the etf.conf file.

It uses the singleton design pattern
"""

from configobj import ConfigObj

class ConfigurationManager(object):
    def __init__(self, config_file_path='./etf.conf'):
        self.conf_path = config_file_path
        self.config = ConfigObj(config_file_path)

    def set_global_config(self, var, val, section = "root"):
        if section == "root":
            section = self.config

        if var in section.keys():
            section[var] = val

        for key, value in section.items():
            if isinstance(value, dict):
                try:
                    self.set_global_config(var, val, value)
                except: pass

    def write(self):
        self.config.write()
