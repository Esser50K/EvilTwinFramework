#!/usr/bin/env python
import sys, os
from termcolor import colored
import logging, traceback
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Shut up Scapy

sys.path.append('./core')
sys.path.append('./utils')

from cmd import Cmd
from utils import etfbanners
from AirCommunicator.aircommunicator import AirCommunicator
from ConfigurationManager.configmanager import ConfigurationManager
from Spawners.spawnmanager import SpawnManager


class ETFCommandLine(Cmd):
    # Cmd is defined as an old style class, therefor inheritance 
    # will not work and class variables have to be declared outside __init__

    # Backend Tools
    configs = ConfigurationManager("./core/ConfigurationManager/etf.conf").config
    aircommunicator = AirCommunicator()
    spawnmanager = SpawnManager()

    basic_commands = ["air", "spawn", "restore", "get", "set", "modeset", "back", "list"]

    air_commands = ["deauthor", "sniffer", "host"]
    air_options = ["start", "stop", "status"]
    air_aplauncher_options = ["copy_ap", "copy_probe", "load", "save", "list_clients"] # copy: copies from aps_list, save: saves an access points details to file, load: loads access point details from file
    air_sniffer_options = ["list_all", "list_aps", "list_probes"]
    air_deauthor_options = ["list_all", "list_bssids", "list_clients", 
                            "add_bssid", "add_client",
                            "del_bssid", "del_client", "flush"]

    spawner_options = ['mitmf', 'beef', 'ettercap', 'sslstrip']

    # Configuration Handling
    current_config_mode = configs["etf"]["aircommunicator"]
    config_mode_string = "etf/aircommunicator/"

    # do and complete of configuration options
    def do_restore(self, args):
        entered = args.split()
        if len(entered) != 1:
            print "[-] Only 1 argument expected after spawn command"

        self.spawnmanager.restore_spawner(args)

    def do_spawn(self, args):
        entered = args.split()
        if len(entered) != 1:
            print "[-] Only 1 argument expected after spawn command"

        try:
            self.spawnmanager.add_spawner(  args, 
                                            self.configs["etf"]["spawner"][args]["system_location"],
                                            " ".join(self.configs["etf"]["spawner"][args]["args"]))
        except KeyError:
            print "[-] Spawner for '{}' does not exist.".format(args)



    def spawner_completion(self, text, line):
        entered = line.split()
        out = None
        if len(entered) == 1:
            out = self.spawner_options
        elif len(entered) == 2:
            out = [option for option in self.spawner_options if option.startswith(text)]

        return out

    def complete_spawn(self, text, line, begidx, endidx):
        return self.spawner_completion(text, line)

    def complete_restore(self, text, line, begidx, endidx):
        return self.spawner_completion(text, line)

    def do_list(self, args):
        is_var = lambda key: (  isinstance(self.current_config_mode[key], str) or 
                                isinstance(self.current_config_mode[key], list))

        print "\n".join([ "{:>20} ={:>20}; ({})".format(key, 
                            self.current_config_mode[key] if is_var(key) else "(dict)",
                            "var" if is_var(key) else "mode")
                        for key in self.current_config_mode.keys()])


    def do_back(self, args):
        mode = [mode for mode in self.config_mode_string.split("/") if mode != '']
        if len(mode) == 1:
            pass
        else:
            mode = mode[:-1]
            self.config_mode_string = ""
            self.current_config_mode = self.configs
            for layer in mode:
                self.current_config_mode = self.current_config_mode[layer]
                self.config_mode_string += layer + "/"

        self.update_prompt()
        

    def do_modeset(self, args):
        arg = args.split()
        if len(arg) != 1:
            print "[-] Only 1 arg expected after 'modeset'"
            return

        try:
            mode = arg[0]
            if not (isinstance(self.current_config_mode[mode], str) or \
                    isinstance(self.current_config_mode[mode], list)):
                self.current_config_mode = self.current_config_mode[mode]
                self.config_mode_string += mode + "/"
                self.update_prompt()
        except KeyError:
            print "'{key}' does not exist in the configuration file".format(key = mode)


    def complete_modeset(self, text, line, begidx, endidx):
        return self.complete_modes(text)

    def do_get(self, args):
        var = args.split()
        if len(var) != 1:
            print "[-] Only 1 arg expected after 'get'"
            return

        try:
            mode = var[0]
            if  isinstance(self.current_config_mode[mode], str) or \
                isinstance(self.current_config_mode[mode], list):

                config, value = mode, self.current_config_mode[mode]
                print "{config} = {value}".format(  config = config, 
                                                    value = self.current_config_mode[mode])
        except KeyError:
            print "'{key}' does not exist in the configuration file".format(key = mode)

    def complete_get(self, text, line, begidx, endidx):
        return self.complete_vars(text)

    def do_set(self, args):
        try:
            splitted_args = args.split()
            if len(splitted_args) == 2:
                var, value = splitted_args[0], splitted_args[1] 
            else:
                var, value = splitted_args[0], splitted_args[1:]

            self.current_config_mode[var] # raise KeyError before assignment if option does not exist
            self.current_config_mode[var] = value
            self.configs.write()
            print "{config} = {value}".format(  config = var, 
                                                value = self.current_config_mode[var])
        except KeyError:
            print "'{key}' does not exist in the configuration file".format(key = mode)

    def complete_set(self, text, line, begidx, endidx):
        return self.complete_vars(text)

    def complete_vars(self, text):
        out = [keyword for keyword  in  self.current_config_mode 
                                    if  keyword.startswith(text) and \
                                        (isinstance(self.current_config_mode[keyword], str) or \
                                        isinstance(self.current_config_mode[keyword], list))]
        return out

    def complete_modes(self, text):
        out = [keyword for keyword  in  self.current_config_mode 
                                    if  keyword.startswith(text) and not \
                                        (isinstance(self.current_config_mode[keyword], str) or \
                                        isinstance(self.current_config_mode[keyword], list))]
        return out
                
    # Air command do and complete

    def sniffer_actions(self, option):
        if option == "list_aps":
            self.aircommunicator.print_sniffed_aps()
        elif option == "list_probes":
            self.aircommunicator.print_sniffed_probes()
        elif option == "list_all":
            self.aircommunicator.print_sniffed_aps()
            self.aircommunicator.print_sniffed_probes()

    def deauthor_actions(self, option):
        air_deauthor_options = ["list_all", "list_bssids", "list_clients", 
                            "add_bssid", "add_client",
                            "del_bssid", "del_client", "flush"]

        if option == "list_bssids":
            self.aircommunicator.print_bssids_to_deauth()
        elif option == "list_clients":
            self.aircommunicator.print_clients_to_deauth()
        elif option == "list_all":
            self.aircommunicator.print_bssids_to_deauth()
            self.aircommunicator.print_clients_to_deauth()
        elif "flush" == option:
            self.aircommunicator.deauthor_flush()

    def deauthor_deladd(self, option, index=0):
        sub_option = option[4:] # cut the 'del_' or 'add_' to get 'bssid' or 'client'

        if "add_" in option:
            self.aircommunicator.deauthor_add(sub_option, index)
        elif "del_" in option:
            self.aircommunicator.deauthor_del(sub_option, index)

    def aplauncher_actions(self, option, index=0):
        if option == "copy_ap":
            self.aircommunicator.airhost_copy_ap(index)
        elif option == "copy_probe":
            self.aircommunicator.airhost_copy_probe(index)
        elif option == "save": # TODO
            pass
        elif option == "load":
            pass
        elif option == "list_clients":
            self.aircommunicator.print_connected_clients()

    def aircommunicator_service(self, service, option):
        if service == "deauthor":
            if option == "start":
                self.aircommunicator.start_deauthentication_attack()
            else:
                self.aircommunicator.stop_air_communications(False, False, True)
        elif service == "host":
            if option == "start":
                self.aircommunicator.start_access_point()
            else:
                self.aircommunicator.stop_air_communications(False, True, False)
        elif service == "sniffer":
            if option == "start":
                self.aircommunicator.start_sniffer()
            else:
                self.aircommunicator.stop_air_communications(True, False, False)

    def do_air(self, args):
        air_command = args.split()

        if len(air_command) == 2:
            tool, option = air_command
            if option in self.air_options:
                self.aircommunicator_service(tool, option)
            # Options other than starting or stopping the service
            elif tool == "sniffer" and option in self.air_sniffer_options:
                self.sniffer_actions(option)
            elif tool == "deauthor" and option in self.air_deauthor_options:
                self.deauthor_actions(option)
            elif tool == "host" and option in self.air_aplauncher_options:
                self.aplauncher_actions(option)
        elif len(air_command) == 3:
            tool, option, index = air_command
            try:
                index = int(index)
            except Exception as e:
                print e, "\n[-] Error: specified index '{}' must be integer".format(str(index))
                return

            if tool == "host" and option in self.air_aplauncher_options:
                self.aplauncher_actions(option, index)
            elif tool == "deauthor" and option in self.air_deauthor_options:
                self.deauthor_deladd(option, index)



    def show_empty_text_options(self, line):
        entered = line.split()
        out = None
        if len(entered) == 1:
            out = self.air_commands
        elif len(entered) == 2:
            if entered[1] == "host":
                out = self.air_aplauncher_options
            elif entered[1] == "sniffer":
                out = self.air_sniffer_options
            elif entered[1] == "deauthor":
                out = self.air_deauthor_options

            out += self.air_options

        return out

    def show_to_complete_options(self, line, text):
        entered = line.split()
        out = None
        if len(entered) == 2:
            # Here the first parameter after 'air' is already complete and the user wants the next
            if entered[1] in self.air_commands:
                out = [text + " "]
            # Here the first parameter after 'air' is incomplete and the user wants completion
            else:
                start = entered[1]
                out = [keyword for keyword in self.air_commands if keyword.startswith(start)]
        elif len(entered) == 3:
            start = entered[2]
            if entered[1] in self.air_commands:
                if entered[1] == "host":
                    out = [keyword for keyword in self.air_aplauncher_options if keyword.startswith(start)]
                elif entered[1] == "sniffer":
                    out = [keyword for keyword in self.air_sniffer_options if keyword.startswith(start)]
                elif entered[1] == "deauthor":
                    out = [keyword for keyword in self.air_deauthor_options if keyword.startswith(start)]

                out += [keyword for keyword in self.air_options if keyword.startswith(start)]
        return out

    def complete_air(self, text, line, begidx, endidx):
        if not text or text == "":
            return self.show_empty_text_options(line)
        else:
            return self.show_to_complete_options(line, text)

    def update_prompt(self):
        self.prompt = "ETF{mode_start}{mode}{mode_end}::> ".format( mode_start = colored("[", "cyan"),
                                                                    mode = colored(cmdline.config_mode_string[:-1], "green"),
                                                                    mode_end = colored("]", "cyan"))

    def do_EOF(self, line): # control-D
        print "Exiting..."
        self.aircommunicator.stop_air_communications(True, True, True)
        self.spawnmanager.restore_all()
        os.system('service networking restart')
        os.system('service network-manager restart')
        return True

    # Just overwriting this method so it doesn't execute the last non-empty line
    def emptyline(self):
        pass


if __name__ == '__main__':
    print etfbanners.get_banner()

    if os.geteuid() != 0:
        print "You are not privileged enough."
        sys.exit(1)

    cmdline = ETFCommandLine()
    cmdline.update_prompt()

    try:
        cmdline.cmdloop()
    except Exception as e:
        print "[-] Exception in command line loop:\n", e
        traceback.print_exc()
        cmdline.aircommunicator.stop_air_communications(True, True, True)
        cmdline.spawnmanager.restore_all()
        os.system('service networking restart')
        os.system('service network-manager restart')