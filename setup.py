#!/usr/bin/env python
import sys, os
sys.path.append('./core')
sys.path.append('./utils')

from textwrap import dedent
from utils.utils import FileHandler

def install_scapy_community():
    print "[+] Preparing to install community version of scapy"
    clone_command           = "hg clone https://bitbucket.org/secdev/scapy-com"
    dpkg_command            = "dpkg --ignore-depends=python-scapy -r python-scapy"
    installation_command    = "cd scapy-com && python setup.py install"
    cleanup_command         = "rm -rf scapy-com"

    print "[+] Cloning scapy-com official repository"
    os.system(clone_command)

    print "[+] Running scapy-com setup installation"
    os.system(installation_command)

    print "[+] Cleaning up the cloned folder after installation"
    os.system(cleanup_command)



# Script starts here
if os.geteuid() != 0:
        print "You are not privileged enough."
        sys.exit(1)

try:
    print "[+] Adding kali-linux repositories to /etc/apt/sources.list"
    apt_source_fhandler = FileHandler("/etc/apt/sources.list")
    apt_source_fhandler.write(dedent("""
                                    deb http://repo.kali.org/kali kali-rolling main non-free contrib
                                    deb-src http://repo.kali.org/kali kali-rolling main non-free contrib
                                    """))
except Exception as e:
    print "[-] This tool is only supported by Debian systems"
    print "[-] You should have apt package manager installed."
    sys.exit(1)

# Dependencies
package_list = ["python-scapy", "dnsmasq", 
                "hostapd-wpe", "python-pyric", 
                "--reinstall mitmproxy", "gnome-terminal", 
                "mitmf", "beef-xss", 
                "ettercap-common", "sslstrip"]

print "[+] Updating apt... (This may take a while)"
os.system("apt-get update")

print "[+] Apt successfully updated, preparing to install packages"
for pkg in package_list:
    try:
        print "[+] Preparing to install '{}'".format(pkg)
        os.system("apt-get install -y {}".format(pkg))

        if pkg == "python-pyric":
            print "[+] Upgrading Pyric version."
            os.system('pip install --upgrade PyRic')

    except Exception as e:
        print e
        print "[-] Installation of package '{}' failed.".format(pkg)

install_scapy_community()
apt_source_fhandler.restore_file()
