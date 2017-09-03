"""
This class is responsible for reading, writing, updating the etf.conf file.

It uses the singleton design pattern
"""

from configobj import ConfigObj

# TODO make set_config method that treats the variable to config as global and looks where it repeats itself
class ConfigurationManager(object):

    class __ConfigurationManager(object):
        def __init__(self, config_file_path):
            self.conf_path = config_file_path
            self.config = ConfigObj(config_file_path)
            self = property(self, self.config.write())

    instance = None

    def __init__(self, config_file_path='./etf.conf'):
        if not ConfigurationManager.instance:
            ConfigurationManager.instance = ConfigurationManager.__ConfigurationManager(config_file_path)
        else:
            ConfigurationManager.instance.conf_path = config_file_path

    def __getattr__(self, name):
        return getattr(self.instance, name)
