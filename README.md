# EvilTwinFramework
A framework for pentesters that facilitates evil twin attacks as well as exploiting other wifi vulnerabilities

This is tool is not for wifi cracking, for that you can use aircrack-ng
After it is cracked you can easily create an evil-twin while 
deauthenticating all users from the real access point

It uses hostapd to create the access point, so it is highly configurable
It uses dnsmasq to run the dhcp and dns services
It uses apache with help of dnsmasq to launch spoofed pages as well as captive portals!

Packet sending and receiving is all done via Scapy
Any contribution affecting the receiving and sending of wireless packets must be done via Scapy
(calling aireplay does not count.)
