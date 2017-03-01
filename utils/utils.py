#!/usr/bin/env python

# This module was written to create some useful classes
# responsible for controlling network configurations
# such as routing tables and network adapter configurations

import os
import signal
import subprocess
from shutil import copy
from etfexceptions import InvalidFilePathException, InvalidConfigurationException
from threading import Thread

DEVNULL = open(os.devnull, 'wb') # Stream used to hide output from another process

class AsyncTask(Thread):
    def __init__(self, cmd=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, screen_output=False):
        self.stdout = stdout
        self.stderr = stderr
        self.cmd = cmd
        self.screen_output = screen_output
        self.exit = False
        super(AsyncTask, self).__init__()

    def set_command(self, command_string):
        self.cmd = command_string

    def async_exec(self):
        process = subprocess.Popen( self.cmd.split(),
                                    stdout=self.stdout,
                                    stderr=self.stderr,
                                    universal_newlines=True)
        output_lines = iter(process.stdout.readline, "")
        for line in output_lines:
            yield line
            if self.exit: break

        process.stdout.close()

    def stop(self):
        self.exit = True

    def run(self):
        if self.screen_output:
            for output_line in self.async_exec():
                print output_line.strip()
                if self.exit: break
        else:
            self.async_exec()

class NetUtils:
    """
    This class is responsible for setting the general
    routing rules by making calls to 'iptables' and 'route'
    """
    
    def flush_iptables(self):
        os.system('iptables -F')
        os.system('iptables -t nat -F')
        os.system('iptables --delete-chain')
        os.system('iptables -t nat --delete-chain')
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

    def accept_forwarding(self, interface): 
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        os.system('iptables -P FORWARD ACCEPT')
        os.system('iptables -A FORWARD --in-interface {interface} -j ACCEPT'.format(
                                                                            interface=interface))

    def set_postrouting_interface(self, interface):
        os.system('iptables -t nat -A POSTROUTING --out-interface {interface} -j MASQUERADE'.format(
                                                                                            interface=interface))

    def set_port_redirection_rule(self, protocol, from_port, to_port, add=True):
        os.system('iptables -t nat -{add} PREROUTING -p {proto} --destination-port {from_port} -j REDIRECT --to-port {to_port}'.format(
                                                                                                add= "A" if add else "D",
                                                                                                proto=protocol,
                                                                                                from_port=from_port,
                                                                                                to_port=to_port))

    def set_protocol_redirection_rule(self, protocol, gateway):
        os.system('iptables -t nat -A PREROUTING -p {protocol} -j DNAT --to {gateway}'.format(
                                                                                protocol=protocol,
                                                                                gateway=gateway))

    def add_routing_rule(self, subnet, netmask, gateway):
        os.system('route add -net {subnet} netmask {netmask} gw {gateway}'.format(
                                                                                subnet=subnet,
                                                                                netmask=netmask,
                                                                                gateway=gateway))

    def delete_routing_rule(self, subnet, netmask, gateway):
        os.system('route del -net {subnet} netmask {netmask} gw {gateway}'.format(
                                                                                subnet=subnet,
                                                                                netmask=netmask,
                                                                                gateway=gateway))

    
class FileHandler(object):
    '''
    This class is mostly for writing configuration files 
    without the need to overwrite the one that already exists
    '''

    def __init__(self, file_path, backup=True):

        if not os.path.isfile(file_path) and backup:
            raise InvalidFilePathException("The specified file: {file_path} does not exist".format(file_path=file_path))

        self.current_file = file_path
        self.original_file = file_path + ".original"

        if backup and not os.path.isfile(file_path + ".original"):
            copy(file_path, file_path + ".original") # Create a backup file with the '.original' extension

        open(self.current_file, 'w').close()

    def restore_file(self):
        if os.path.exists(self.original_file):
            copy(self.original_file, self.current_file)
            os.remove(self.original_file)

    def write(self, string, mode='w'):
        if os.path.exists(self.current_file):
            with open(self.current_file, mode) as filepath:
                filepath.write(string)
                filepath.close()




