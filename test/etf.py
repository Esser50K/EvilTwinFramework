#!/usr/bin/env python

import os
import aplauncher
import networkmanager
from configmanager import ConfigurationManager as CMan
import time

if __name__ == '__main__':
	try:
		if os.path.exists('./etf.conf'):
			CMan('./etf.conf')
		else:
			CMan()
		nm = networkmanager.NetworkManager()
		nm.iptables_redirect('wlan1', 'wlan0')
		nm.configure_interface('wlan1', '192.168.2.1')
		nm.set_mac_and_unmanage('wlan1', 'aa:bb:cc:dd:ee:ff')
		apl = aplauncher.APLauncher("/etc/dnsmasq.conf", "/etc/hostapd/hostapd_temp.conf")
		apl.write_dnsmasq_configurations('wlan1', '192.168.2.1', ['192.168.2.2', '192.168.2.254'], ['8.8.8.8'])
		apl.write_hostapd_configurations(interface='wlan1', bssid='aa:bb:cc:dd:ee:ff', encryption="wpa2", password="tttttttt")
		apl.start_dnsmasq()
		apl.start_access_point('wlan1')
		time.sleep(100)
		raise KeyboardInterrupt
	except KeyboardInterrupt:
		apl.stop_dnsmasq()
		apl.stop_access_point()
		apl.restore_config_files()
		nm.cleanup()
