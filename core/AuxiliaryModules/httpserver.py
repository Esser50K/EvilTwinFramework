"""
This class uses apache to launch an http/https server
It can be configured as a fake captive portal for phishing attacks
It can also be used for serving spoofed dns pages
"""

import os, shutil
from subprocess import Popen
from utils.utils import DEVNULL
from textwrap import dedent

class HTTPServer(object):

	def __init__(self, apache_config_path, apache_root_path):

		self.apache_config_path = apache_config_path
		self.apache_root_path = apache_root_path
		self.apache_running = False

	def start_server(self, start = True):
		success = os.system("service apache2 {start}".format(start = "restart" if start else "stop"))
		if success:
			self.apache_running = start

		return success

	def reset_conf(self):
		for page in os.listdir(self.apache_config_path):
			Popen("a2dissite {}".format(page).split(), stdout=DEVNULL, stderr=DEVNULL)

	# This method grabs the pages present in the data/spoofpages/{domain_name}
	def add_site(self, domain_name):
		if not os.path.exists("data/spoofpages/" + domain_name):
			print "[-] Cannot add '{}' because corresponding folder is missing from 'data/spoofpages/'".format(domain_name)
			return

		spoofpage_path = "data/spoofpages/" + domain_name
		apache_path = self.apache_root_path + domain_name

		if os.path.exists(apache_path):
			shutil.rmtree(apache_path)
		shutil.copytree(spoofpage_path, apache_path)

	def configure_page_in_apache(	self, domain_name, domain_alias = [], 
									ssl = False, captive_portal_mode = False):
		apache_http_config_file = "{conf_path}{domain}.http.conf".format(	conf_path = self.apache_config_path,
																			domain = domain_name)
		apache_https_config_file = "{conf_path}{domain}.https.conf".format(	conf_path = self.apache_config_path,
																			domain = domain_name)
		ssl_config_string = dedent(	"""
									SSLEngine on
									SSLCertificateFile	/var/www/html/{domain}/{domain}.cert
									SSLCertificateKeyFile /var/www/html/{domain}/{domain}.key
									""").format(domain = domain_name)

		captive_portal_config = dedent(	"""
										<If "%{{HTTP_HOST}} != '{domain}'">
											Redirect "/" "http://{domain}"
										</If>
										""").format(domain = domain_name) 
										#var has to be hardcoded because of the format function

		apache_domain_config = dedent(	"""
										ServerName {domain}
										ServerAlias {alias}
										ServerAdmin admin@{domain}
										DocumentRoot /var/www/html/{domain}
										{captive_portal_config}
										ErrorDocument 404 {domain}/index.php
										""").format(domain = domain_name, alias = " ".join(map(str, domain_alias)),
													captive_portal_config = (captive_portal_config if captive_portal_mode else ""))

		apache_http_config_string = dedent(	"""
											<VirtualHost *:80>
												{domain_config}
												ErrorLog ${{APACHE_LOG_DIR}}/error.log
												CustomLog ${{APACHE_LOG_DIR}}/access.log combined
											</VirtualHost>
											""").format(domain_config = apache_domain_config)

		apache_https_config_string = dedent("""
											<IfModule mod_ssl.c>
												<VirtualHost _default_:443>
													{domain_config}
													{ssl_config}
												</VirtualHost>
											</IfModule>
											""").format(domain_config = apache_domain_config,
														ssl_config = ssl_config_string if ssl else "")

		# Command too long for single code line
		openssl_keygen_string = "openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 "
		openssl_keygen_string += "-subj /C=US/ST=NY/L=NY/O={domain}/CN={domain} ".format(domain = domain_name)
		openssl_keygen_string += "-keyout /var/www/html/{domain}/{domain}.key ".format(domain = domain_name)
		openssl_keygen_string += "-out /var/www/html/{domain}/{domain}.cert".format(domain = domain_name)

		if ssl:
			print "[+] Creating ssl private key and certificate for '{}'".format(domain_name)
			Popen(openssl_keygen_string.split(), stdout=DEVNULL, stderr=DEVNULL).wait()
		with open(apache_http_config_file, "w") as http_config:
			http_config.write(apache_http_config_string)
		with open(apache_https_config_file, "w") as https_config:
			https_config.write(apache_https_config_string)
		Popen("a2ensite {http_config}".format(http_config = apache_http_config_file.split("/")[-1]).split(), stdout=DEVNULL, stderr=DEVNULL)
		Popen("a2ensite {https_config}".format(https_config = apache_https_config_file.split("/")[-1]).split(), stdout=DEVNULL, stderr=DEVNULL)


