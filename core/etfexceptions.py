'''
Module where all custom exceptions are specified for ETF
'''

class MissingConfigurationFileException(Exception):
    """
    Exception to raise if mandatory configuration file is not specified
    """
    def __init__(self, message):
        self.error_msg = "[-] Missing Configuration File:\n" + message
        Exception.__init__(self, self.error_msg)

class InvalidConfigurationException(Exception):
    """
    Exception to raise in case of trying to write invalid configurations to a file
    """

    def __init__(self, message):
        self.error_msg = "[-] Invalid Configurations:\n" + message
        Exception.__init__(self, self.error_msg)

class InvalidFilePathException(Exception):
    """
    Exception raise in case of trying to write invalid configurations to a file
    """

    def __init__(self, message):
        self.error_msg = "[-] Invalid File Path:\n" + message
        Exception.__init__(self, self.error_msg)
