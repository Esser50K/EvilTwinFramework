#!/usr/bin/env python
import sys, os
from termcolor import colored
import logging, traceback
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

os.chdir(os.path.dirname(sys.argv[0])) # Change working directory
sys.path.append('./core')
sys.path.append('./utils')

from cmd import Cmd
from utils import etfbanners
from AirCommunicator.aircommunicator import AirCommunicator
from AirCommunicator.airscanner import AccessPoint, WiFiClient, ProbeInfo
from AirCommunicator.airdeauthor import DeauthAP, DeauthClient
from AirCommunicator.aircracker import WPAHandshake
from AuxiliaryModules.aplauncher import Client
from ConfigurationManager.configmanager import ConfigurationManager
from MITMCore.etfitm import EvilInTheMiddle
from Spawners.spawnmanager import SpawnManager


class ETFConsole(Cmd):
	# Cmd is defined as an old style class, therefor inheritance 
	# will not work and class variables have to be declared outside __init__

	# Backend Tools
	configs = ConfigurationManager("./core/ConfigurationManager/etf.conf").config
	aircommunicator = AirCommunicator()
	etfitm			= EvilInTheMiddle()
	spawnmanager 	= SpawnManager()

	# Static strings to help with autocompletion

	basic_commands = [  "start", "stop", "status", 
						"spawn", "restore",
						"get", "set", "config", "back", "listargs",
						"copy", "add", "del", "show"  ]

	services = ["airhost", "airscanner", "airdeauthor", "aircracker", "mitmproxy"]
	aux_services = ["aplauncher", "dnsmasqhandler"]
	spawners = ["mitmf", "beef-xss", "ettercap", "sslstrip"]

	filter_keywords = ["where", "only"]
	plugin_keyword = ["with"]

	airhost_plugins = ["dnsspoofer", "credentialprinter", "credentialsniffer", "karma"]
	airscanner_plugins = ["packetlogger", "selfishwifi", "credentialsniffer"]
	airdeauthor_plugins = ["credentialsniffer"]
	aircracker_types = ["wpa_crackers", "half_wpa_crackers"]
	aircrackers = ["cowpatty", "aircrack-ng", "halwpaid"]
	mitmproxy_plugins = ["downloadreplacer", "beefinjector", "peinjector"]

	copy_options = ["ap", "probe"]
	add_del_options = ["aps", "clients"] 								 	# Meant to be followed by ID
	show_options = ["sniffed_aps", "sniffed_probes", "sniffed_clients",
					"deauth_aps", "deauth_clients", "connected_clients",
					"wpa_handshakes", "half_wpa_handshakes"] 				# Meant to be followed by filter
	crack_options = ["wpa_handshakes", "half_wpa_handshakes"]				# Meant to be followed by ID


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
			self.spawnmanager.add_spawner(args)
		except KeyError as e:
			print e
			print "[-] Spawner for '{}' does not exist.".format(args)

	def spawner_completion(self, text, line):
		entered = line.split()
		out = None
		if len(entered) == 1:
			out = self.spawners
		elif len(entered) == 2:
			out = [option for option in self.spawners if option.startswith(text)]

		return out

	def complete_spawn(self, text, line, begidx, endidx):
		return self.spawner_completion(text, line)

	def complete_restore(self, text, line, begidx, endidx):
		return self.spawner_completion(text, line)

	def do_listargs(self, args):
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

	def do_config(self, args):
		arg = args.split()
		if len(arg) != 1:
			print "[-] Only 1 arg expected after 'config'"
			return

		try:
			config_key = arg[0]
			dict_string, config = self._look_for_config("", self.configs, config_key)
			dict_string = "/".join(dict_string[:-1].split("/")[::-1]) # the output string is from bottom to top, we reverse
			self.current_config_mode = config 
			self.config_mode_string = dict_string
			self.update_prompt()
		except Exception:
			print "'{key}' does not exist in the configuration file".format(key = config_key)

	def _look_for_config(self, dict_string, dict_root, dict_key):
		if dict_key in dict_root:
			dict_string += dict_key + "/"
			return (dict_string, dict_root[dict_key])

		for key, value in dict_root.items():
			if isinstance(value, dict):
				try:
					dict_string, item = self._look_for_config(dict_string, value, dict_key)
					dict_string += key + "/"
					if item is not None:
						return (dict_string, item)
				except: pass
				

	def complete_config(self, text, line, begidx, endidx):
		args = line.split()
		all_configs = 	self.services + \
						self.aux_services + \
						self.spawners + \
						self.airscanner_plugins + \
						self.airhost_plugins + \
						self.airdeauthor_plugins + \
						self.aircracker_types + \
						self.aircrackers + \
						self.mitmproxy_plugins

		if len(args) == 1:
			return all_configs
		elif len(args) == 2:
			return [config for config in all_configs if config.startswith(args[1])]

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
			#self.current_config_mode[var] = value
			self._set_global_config(self.configs, var, value)
			self.configs.write()
			print "{config} = {value}".format(  config = var,
												value = self.current_config_mode[var])
		except KeyError:
			print "'{key}' does not exist in the configuration file".format(key = var)

	def _set_global_config(self, dict_root, var, val):
		if var in dict_root.keys():
			dict_root[var] = val
			
		for key, value in dict_root.items():
			if isinstance(value, dict):
				try:
					self._set_global_config(value, var, val)
				except: pass


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
				

	# Copy Add Del
	def do_copy(self, args):
		args = args.split()
		if len(args) == 2:
			try:
				id = int(args[-1]) # line should be something like "copy ap 4"
			except ValueError:
				print "[-] ID must be an integer value"
				print "Copy syntax: copy [option] [ID]"
				return 
			if args[0] == "ap":
				self.aircommunicator.airhost_copy_ap(id)
			elif args[0] == "probe":
				self.aircommunicator.airhost_copy_probe(id)


	def complete_copy(self, text, line, begidx, endidx):
		entered = line.split()
		if len(entered) == 1:
			if not text or text == "":
				return self.copy_options
		elif len(entered) == 2:
			start = entered[1]
			return [option for option in self.copy_options if option.startswith(start)]


	def do_add(self, args):
		args = args.split()
		if len(args) >= 1:
			filter_string = self._parse_filter_string(args)
			self.aircommunicator.deauthor_add(args[0], filter_string)

	def do_del(self, args):
		args = args.split()
		if len(args) >= 1:
			filter_string = self._parse_filter_string(args)
			self.aircommunicator.deauthor_del(args[0], filter_string)

	def complete_add(self, text, line, begidx, endidx):
		return self.complete_addel(line, text)

	def complete_del(self, text, line, begidx, endidx):
		return self.complete_addel(line, text)

	def _parse_filter_string(self, args):
		filter_string = None
		if len(args) == 3:
			try:
				id = int(args[2])
				filter_string = "where id = {}".format(str(id))
			except:
				pass
		elif len(args) > 3:
			filter_string = " ".join(args[1:])

		return filter_string

	def complete_addel(self, line, text):
		if not text or text == "":
			return self.show_empty_text_addel_options(line)
		else:
			return self.show_to_complete_addel_options(line, text)

	def show_empty_text_addel_options(self, line):
		entered = line.split()
		out = None
		if len(entered) < 3:
			out = self.complete_filter_command(self.add_del_options, "", entered)
		elif len(entered) >= 3:
			# list filter args (id, ssid, bssid, channel, etc...)
			addel = entered[0]
			if addel == "add":
				if entered[1] == "aps":
					out = vars(AccessPoint()).keys()
				elif entered[1] == "clients":
					out = vars(ProbeInfo()).keys()
			elif addel == "del":
				if entered[1] == "aps":
					out = vars(DeauthAP()).keys()
				elif entered[1] == "clients":
					out = vars(DeauthClient()).keys()

		return out

	def show_to_complete_addel_options(self, line, text):
		entered = line.split()
		out = None
		if len(entered) <= 3:
			out = self.complete_filter_command(self.add_del_options, text, entered)
		elif len(entered) > 3:
			start = entered[-1]
			addel = entered[0]
			if addel == "add":
				if entered[1] == "aps":
					out = [keyword for keyword in vars(AccessPoint()).keys() if keyword.startswith(start)]
				elif entered[1] == "clients":
					out = [keyword for keyword in vars(ProbeInfo()).keys() if keyword.startswith(start)]
			elif addel == "del":
				if entered[1] == "aps":
					out = [keyword for keyword in vars(DeauthAP()).keys() if keyword.startswith(start)]
				elif entered[1] == "clients":
					out = [keyword for keyword in vars(DeauthClient()).keys() if keyword.startswith(start)]

		return out

	def complete_filter_command(self, options, text, entered):
		out = None
		if not text or text == "":
			if len(entered) == 1:
				out = options
			elif len(entered) == 2:
				out = self.filter_keywords
		else:
			if len(entered) == 2:
				# Here the first parameter after 'show' is already complete and the user wants the next
				if entered[1] in options:
					out = [text + " "]
				# Here the first parameter after 'show' is incomplete and the user wants completion
				else:
					start = entered[1]
					out = [keyword for keyword in options if keyword.startswith(start)]
			elif len(entered) == 3:
				# Completion for the 'where' or 'only' keyword
				if entered[2] in self.filter_keywords:
					out = [text + " "]
				else:
					start = entered[2]
					out = [keyword for keyword in self.filter_keywords if keyword.startswith(start)]
		return out

	# Show

	def do_show(self, args):
		args = args.split()
		if len(args) >= 1:
			option = args[0]
			filter_string = ""
			if len(args) >= 2:
				filter_string = " ".join(args[1:])

			if option == "sniffed_aps":
				self.aircommunicator.print_sniffed_aps(filter_string)
			elif option == "sniffed_clients":
				self.aircommunicator.print_sniffed_clients(filter_string)
			elif option == "sniffed_probes":
				self.aircommunicator.print_sniffed_probes(filter_string)
			elif option == "deauth_aps":
				self.aircommunicator.print_aps_to_deauth(filter_string)
			elif option == "deauth_clients":
				self.aircommunicator.print_clients_to_deauth(filter_string)
			elif option == "connected_clients":
				self.aircommunicator.print_connected_clients(filter_string)
			elif option == "wpa_handshakes":
				self.aircommunicator.print_captured_handshakes(filter_string, False)
			elif option == "half_wpa_handshakes":
				self.aircommunicator.print_captured_handshakes(filter_string, True)



	def complete_show(self, text, line, begidx, endidx):
		if not text or text == "":
			return self.show_empty_text_show_options(line)
		else:
			return self.show_to_complete_show_options(line, text)

	def show_empty_text_show_options(self, line):
		entered = line.split()
		out = None
		if len(entered) < 3:
			out = self.complete_filter_command(self.show_options, "", entered)
		elif len(entered) >= 3:
			# list filter args (id, ssid, bssid, channel, etc...)
			if entered[1] == "sniffed_aps":
				out = vars(AccessPoint()).keys()
			elif entered[1] == "sniffed_clients":
				out = vars(WiFiClient()).keys()
			elif entered[1] == "sniffed_probes":
				out = vars(ProbeInfo()).keys()
			elif entered[1] == "deauth_aps":
				out = vars(DeauthAP()).keys()
			elif entered[1] == "deauth_clients":
				out = vars(DeauthClient()).keys()
			elif entered[1] == "connected_clients":
				out = vars(Client()).keys()
			elif entered[1] == "wpa_handshakes" or entered[1] == "half_wpa_handshakes":
				out = vars(WPAHandshake()).keys()

		return out

	def show_to_complete_show_options(self, line, text):
		entered = line.split()
		out = None
		if len(entered) < 4:
			out = self.complete_filter_command(self.show_options, text, entered)
		elif len(entered) >= 4:
			start = entered[-1]
			if entered[1] in self.show_options:
				if entered[1] == "sniffed_aps":
					out = [keyword for keyword in vars(AccessPoint()).keys() if keyword.startswith(start)]
				elif entered[1] == "sniffed_clients":
					out = [keyword for keyword in vars(WiFiClient()).keys() if keyword.startswith(start)]
				elif entered[1] == "sniffed_probes":
					out = [keyword for keyword in vars(ProbeInfo()).keys() if keyword.startswith(start)]
				elif entered[1] == "deauth_aps":
					out = [keyword for keyword in vars(DeauthAP()).keys() if keyword.startswith(start)]
				elif entered[1] == "deauth_clients":
					out = [keyword for keyword in vars(DeauthClient()).keys() if keyword.startswith(start)]
				elif entered[1] == "connected_clients":
					out = [keyword for keyword in vars(Client()).keys() if keyword.startswith(start)]
				elif entered[1] == "wpa_handshakes" or entered[1] == "half_wpa_handshakes":
					out = [keyword for keyword in vars(WPAHandshake()).keys() if keyword.startswith(start)]
		return out


	# Start

	def do_start(self, args):
		args = args.split()
		if len(args) >= 1:
			service = args[0]
			plugins = []
			if "with" in args:
				plugins = args[args.index("with")+1:]

			if "air" in service:
				self.aircommunicator.service(service, "start", plugins)
			elif service == "mitmproxy":
				self.start_mitmproxy(plugins)

	def start_mitmproxy(self, plugins):
		mitm_configs = self.configs["etf"]["mitmproxy"]
		try:
			listen_port = int(mitm_configs["lport"]) # Verify if it is integer
			listen_host = mitm_configs["lhost"] if len(mitm_configs["lhost"].split(".")) == 4 else "127.0.0.1"
			ssl = mitm_configs["ssl"].lower() == "true"
			client_cert = mitm_configs["client_cert"]
			certs 		= mitm_configs["certs"]
			if type(certs) is not list and certs != "":
				certs = [certs]
			elif certs == "":
				certs = []

			certs = map(lambda x: x.split("=") if "=" in x else ["*", x], certs)

			mitm_plugins = []
			for plugin in plugins:
				if plugin in self.mitmproxy_plugins:
					mitm_plugins.append(plugin)

		except Exception as e:
			print "[-] Something is wrong with the configuration of mitmproxy:\n", e
			return

		self.etfitm.pass_config(listen_host, listen_port, ssl, client_cert, certs, mitm_plugins)
		self.etfitm.start()

	def do_stop(self, args):
		args = args.split()
		if len(args) >= 1:
			service = args[0]
			if "air" in service:
				self.aircommunicator.service(service, "stop")
			elif service == "mitmproxy":
				self.etfitm.stop()


	def complete_start(self, text, line, begidx, endidx):
		return self._complete_basic(line, text)

	def complete_stop(self, text, line, begidx, endidx):
		return self._complete_basic(line, text)

	def complete_status(self, text, line, begidx, endidx):
		return self._complete_basic(line, text)

	def _complete_basic(self, line, text):
		if not text or text == "":
			return self.show_empty_text_start_options(line)
		else:
			return self.show_to_complete_start_options(line, text)


	def show_empty_text_start_options(self, line):
		entered = line.split()
		out = None
		if len(entered) == 1:
			out = self.services
		elif len(entered) == 2:
			out = self.plugin_keyword
		elif len(entered) >= 3:
			if entered[1] == "airhost":
				out = self.airhost_plugins
			elif entered[1] == "airscanner":
				out = self.airscanner_plugins
			elif entered[1] == "airdeauthor":
				out = self.airdeauthor_plugins
			elif entered[1] == "mitmproxy":
				out = self.mitmproxy_plugins

		return out

	def show_to_complete_start_options(self, line, text):
		entered = line.split()
		out = None
		if len(entered) == 2:
			# Here the first parameter after 'air' is already complete and the user wants the next
			if entered[1] in self.services:
				out = [text + " "]
			# Here the first parameter after 'air' is incomplete and the user wants completion
			else:
				start = entered[1]
				out = [keyword for keyword in self.services if keyword.startswith(start)]
		elif len(entered) == 3:
			# Completion for the 'with' keyword
			if entered[2] in self.plugin_keyword:
				out = [text + " "]
			else:
				out = self.plugin_keyword
		elif len(entered) >= 4:
			start = entered[-1]
			if entered[1] in self.services:
				if entered[1] == "airhost":
					out = [keyword for keyword in self.airhost_plugins if keyword.startswith(start)]
				elif entered[1] == "airscanner":
					out = [keyword for keyword in self.airscanner_plugins if keyword.startswith(start)]
				elif entered[1] == "airdeauthor":
					out = [keyword for keyword in self.airdeauthor_plugins if keyword.startswith(start)]
				elif entered[1] == "mitmproxy":
					out = [keyword for keyword in self.mitmproxy_plugins if keyword.startswith(start)]

		return out

	def do_crack(self, args):
		args = args.split()
		try:
			id, is_half = int(args[1]), "half" in args[0]
		except:
			print "[-] ID must be int"
			return
		self.aircommunicator.crack_handshake(id, is_half)		

	def complete_crack(self, text, line, begidx, endidx):
		out = None
		entered = line.split()

		if not text or text == "":
			if len(entered) == 1:
				out = self.crack_options
		else:
			if len(entered) == 2:
				if entered[1] in self.crack_options:
					out = [text + " "]
				else:
					out = [keyword for keyword in self.crack_options if keyword.startswith(entered[1])]
		return out

	def update_prompt(self):
		self.prompt = "ETF{mode_start}{mode}{mode_end}::> ".format( mode_start = colored("[", "cyan"),
																	mode = colored(console.config_mode_string, "green"),
																	mode_end = colored("]", "cyan"))

	def do_EOF(self, line): # control-D
		print "Exiting..."
		self.aircommunicator.stop_air_communications(True, True, True)
		self.etfitm.stop()
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
		print "You can't handle this yet."
		sys.exit(1)

	console = ETFConsole()
	console.update_prompt()

	try:
		console.cmdloop()
	except Exception as e:
		print "[-] Exception in command line loop:\n", e
		traceback.print_exc()
		console.aircommunicator.stop_air_communications(True, True, True)
		console.etfitm.stop()
		console.spawnmanager.restore_all()
		os.system('service networking restart')
		os.system('service network-manager restart')