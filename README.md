# EvilTwinFramework
A framework for pentesters that facilitates evil twin attacks as well as exploiting other wifi vulnerabilities

This is tool is not for wifi cracking, for that you can use aircrack-ng
After it is cracked you can easily create an evil-twin while 
deauthenticating all users from the real access point

It uses hostapd-wpe to create the access point, so it is highly configurable
It uses dnsmasq to run the dhcp and dns services
It uses apache with help of dnsmasq to launch spoofed pages as well as captive portals!

Packet sending and receiving is all done via Scapy!

# Usage

For now there only is a console interface that is very easy to use and has tab completion!
The whole thing wil work according to the etf.conf file.
You can view and change all configurations via de console, just type:

> config <tab> 

to list the modules available for configuration.
While working on the console type:

> listargs

to view the available parameters, then type:

> set <parameter> <value>

to change it.
If a parameter is (dict) it means it is another configurable module within.

To start an access point make sure you have it configured correctly, type:

> config airhost

check if everything is ok

> config aplauncher

check if everything is ok

> config dnsmasqhandler

check if everything is ok adn start the access point

> start airhost

You can also configure an access point by copying one that is nearby.
Start scanning:

> config airscanner

check if everything is ok

> start airscanner

... wait ...

> show sniffed_aps

This lists the sniffed access points with their ids

> copy ap <id>

OR

> show sniffed_probes
> copy probe <id>

Then start the fake access point

> start airhost


If you have an extra WiFi adapter you can deauthenticate others from their network while running the acces point.
To add access points or clients to be deauthenticated type:

> show sniffed_aps
> add aps <filter_string>

The filter_string follows an easy syntax, it goes:
<filter_keyword> <filter_args>
The args can be any of the column names listed in the table.
The filter keywords are 'where' inclusive filtering or 'only' for exclusive filtering, examples:

This will add the access point whose id is 5 to the deauthentication list:

> add aps where id = 5

This will add the access point whose ssid is 'StarbucksWifi' to the deauthentication list:

> add aps where ssid = StarbucksWifi

This will add the access point whose encryption type has 'wpa' OR 'opn' to the deauthentication list:

> add aps where crypto = wpa, crypto = opn

This will add the access point whose ssid id 'freewifi' AND is on channel 6 to the deauthentication list:

> add aps only ssid = freewifi, channel = 6

Now make sure the interface used for the deuathentication attack 
is not the same as the one used for the fake access point while it is running.

> config airdeauthor
> listargs

After all that run the deauthor:

> start airdeauthor

Same can be done when deleting from the deauth list with the 'del' command.
The 'show' command can also be followed by a filter string


Contributors can program Plugins in python either for the airscanner or airhost or airdeauthor.