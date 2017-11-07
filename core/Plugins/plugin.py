"""
Template Plugin class to be subclassed.
"""

class Plugin(object):
    """
    Base class for Wi-Fi plugins.
    """

    def __init__(self, config, name):
        self.name = name
        self.config = config[name]

    def restore(self):
        """
        To be called when done with main service as cleanup method.
        """
        pass

class AirScannerPlugin(Plugin):
    """
    Base class for AirScanner plugins.
    """

    def __init__(self, config, name):
        """
        The AirScannerPlugin constructor.
        """
        super(AirScannerPlugin, self).__init__(config, name)

    def pre_scanning(self):
        """
        This method is run right before the packet capture starts.
        """
        pass

    def handle_packet(self, packet):
        """
        This method is called for every received packet.
        """
        pass

    def post_scanning(self):
        """
        This method is called right after the packet capture has finished.
        """
        pass


class AirHostPlugin(Plugin):
    """
    Base class for AirHost plugins.
    """

    def __init__(self, config, name):
        super(AirHostPlugin, self).__init__(config, name)

    def pre_start(self):
        """
        This method is called right before launching the access point.
        """
        pass

    def post_start(self):
        """
        This method is called right after launching the access point.
        """
        pass

    def pre_stop(self):
        """
        This method is called right before stopping the access point.
        """
        pass

    def post_stop(self):
        """
        This method is called right after stopping the access point.
        """
        pass

class AirInjectorPlugin(Plugin):
    """
    Base class for AirInjector plugins.
    """

    def __init__(self, config, name):
        super(AirInjectorPlugin, self).__init__(config, name)
        self.packets = set()
        self.should_stop = False
        self.injection_socket = None

    def set_injection_socket(self, L2socket):
        """
        Attribute a socket to be used for the injection attack.
        """
        self.injection_socket = L2socket

    def interpret_targets(self, ap_targets, client_targets):
        """
        This method receives AP and/or Client targets.

        The specific injector will interpret what to do and create the corresponding packets.
        """
        pass

    def inject_packets(self):
        """
        The packet created in interpret_targets are sent in this method as the user specifies.
        """
        pass

    def pre_injection(self):
        """
        This method is called right before the injection attack.
        """
        pass

    def post_injection(self):
        """
        This method is called right after the injection attack.
        """
        pass
