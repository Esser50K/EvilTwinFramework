#!/usr/bin/env python
import sys, os
sys.path.append('./core')
sys.path.append('./utils')

from textwrap import dedent
from utils.utils import FileHandler

def install_scapy_git():
    print "[+] Preparing to install latest version of scapy from git."
    clone_command           = "git clone https://github.com/secdev/scapy.git"
    installation_command    = "cd scapy && python setup.py install"
    cleanup_command         = "rm -rf scapy"

    print "[+] Cloning scapy official repository"
    os.system(clone_command)

    print "[+] Running scapy setup installation"
    os.system(installation_command)

    print "[+] Cleaning up the cloned folder after installation"
    os.system(cleanup_command)

# Script starts here
if os.geteuid() != 0:
        print "You are not privileged enough."
        sys.exit(1)

try:
    print "[+] Adding Kali-Linux repository pgp key tou your system"
    os.system("apt-key adv --keyserver pgp.mit.edu --recv-keys ED444FF07D8D0BF6")
    print "[+] Temporarily Adding Kali-linux repositories to /etc/apt/sources.list"
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
core_packages = [
                    "python-scapy", "dnsmasq", "hostapd-wpe",
                    "python-prettytable", "python-termcolor",
                    "python-configobj", "python-netaddr",
                    "--reinstall mitmproxy", "gnome-terminal"
                ]

pip_upgrade_packages =  [
                            "PyRic",
                            "cmd2",
                            "jsonpickle"
                        ]

spawner_packages =  [
                        "mitmf", "beef-xss",
                        "ettercap-common", "sslstrip"
                    ]

if len(sys.argv) > 1:
    print sys.argv[1]
    install_spawners = sys.argv[1] in ["y", "yes"]
else:
    spawner_package_install_string =    "Spawner Packages are:\n" + "\n".join(spawner_packages) + \
                                        "\nDo you want to install spawner packages too? [y/n]: "
    install_spawners = raw_input(spawner_package_install_string).lower() in ["y", "yes"]

package_list = core_packages + spawner_packages if install_spawners else core_packages

print "[+] Updating apt... (This may take a while)"
os.system("apt-get update")

core_successful = True
fully_successful = True
print "[+] Apt successfully updated, preparing to install packages"
for pkg in package_list:
    try:
        print "[+] Preparing to install '{}'".format(pkg)
        os.system("apt-get install -y {}".format(pkg))
    except Exception as e:
        print e
        print "[-] Installation of package '{}' failed.".format(pkg)
        if pkg in core_packages:
            core_successful = False
        fully_successful = False

for pkg in pip_upgrade_packages:
    try:
        print "[+] Installing/Upgrading {} version.".format(pkg)
        os.system("pip install --upgrade {}".format(pkg))
    except Exception as e:
        print e
        print "[-] Error trying to upgrade '{}' maybe python-pip is not installed..."
        fully_successful = False
        core_successful = False

print "[+] Now installing scapy from github."
install_scapy_git()

success_string =    "[+] Every package was installed successfully. ETF should be ready to go!\n"
spawners_error =    "[-] Core packages were installed successfully. Some Spawner packages were not.\n" + \
                    "You can try to install them manually later.\n"
core_error     =    "[-] One or more core packages failed to install. ETF is not set up.\n"

if fully_successful:
    print success_string
elif not core_successful:
    print core_error
else:
    print spawners_error

print "[+] Restoring your /etc/apt/sources.list file."
apt_source_fhandler.restore_file()
