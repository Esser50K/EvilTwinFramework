import sys, os
from subprocess import call

class WPACracker(object):

    def __init__(self,  name, location,
                        ssid_flag, pcap_flag, wordlist_flag,
                        wordlist_file = None, word_generator_prepend_string = None):
        self.name = name
        self.location = location
        self.ssid_flag = ssid_flag
        self.pcap_flag = pcap_flag
        self.wordlist_flag = wordlist_flag
        self.word_generator_prepend_string = word_generator_prepend_string

        self.ssid = None
        self.pcap_file = None
        self.wordlist_file = wordlist_file

    def generate_execution_string(self):
        if  not (self.ssid is not None or self.pcap_file is not None or
                (self.wordlist_file is not None or self.word_generator_prepend_string is not None)):
            print "[-] Not enough arguments to start dictionary attack."
            return

        common_string = "{location}./{name} {ssid_flag} \"{ssid}\" {pcap_flag} \"{pcap_file}\" {wordlist_flag}".format(
                                                                            location = self.location,
                                                                            name = self.name,
                                                                            ssid_flag = self.ssid_flag,
                                                                            ssid = self.ssid,
                                                                            pcap_flag = self.pcap_flag,
                                                                            pcap_file = self.pcap_file,
                                                                            wordlist_flag = self.wordlist_flag)
        if self.wordlist_file is not None:
            final_string = common_string + " \"{}\"".format(self.wordlist_file)
        elif self.word_generator_prepend_string is not None:
            final_string = self.word_generator_prepend_string + " | " + common_string

        return final_string

    def spawn_cracker(self):
        execution_string = self.generate_execution_string() + "\n"
        with open("rcfile.sh", "w") as rcfile:
            shebang = "#!/bin/sh\n"
            back_to_bash = "exec bash"
            rcfile.write(shebang + execution_string + back_to_bash)

        os.system("chmod +x rcfile.sh")
        if execution_string is not None:
            print "[+] Called:", execution_string
            call("sudo gnome-terminal -e".split() + [ "./rcfile.sh" ])
        os.system("rm rcfile.sh")
