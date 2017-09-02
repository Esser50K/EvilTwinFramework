# EvilTwinFramework
A framework for pentesters that facilitates evil twin attacks as well as exploiting other wifi vulnerabilities

It uses <b>hostapd-wpe</b> to create the access point, so it is highly configurable.

It uses <b>dnsmasq</b> to run the dhcp and dns services.

It uses <b>apache</b> with help of dnsmasq to launch spoofed webpages as well as captive portals!

Packet sending and receiving is all done via <b>Scapy!</b>

# Motivation

The <b>Evil Twin Framework</b> is meant to replace all existing Wi-Fi hacking tools by integrating all features necessary for Wi-Fi penetration testing in one framework. The 3 core features needed are:

<b>Packet Sniffing</b>

<b>Packet Injection</b>

<b>Access Point Creation</b>

All Wi-Fi attacks can be implemented with one or a combination of these core features. By having this platform it will always be possible to contribute with new Wi-Fi attacks that depend on these features.

# Features

<b>All Forms of Evil Twin AP</b>

The Evil Twin Framework, with the help of hostapd can mimick any type of Wi-Fi Network. And by using the hostapd-wpe patch it is easy to get WPA-EAP credentials.

One can configure it as a catch-all honeypot to find out the encryption type of a network that was probed for.

One can even create a karma attack and mimick many networks with different ssids on the same Wi-Fi card (as long as it supports ap-mesh mode). This can be done manually, if you want different encryption types for different networks, or automatically. The automation works by sniffing for popular probe requests and then creating the most popular one according to how many virtual access points you Wi-Fi card supports.

<b>Handshake and Credential Logging</b>

As said before, with the help of hostapd-wpe WPA-EAP credential sniffing is easy!

You can also spoof DNS with dnsmasq and even create captive-portals to force browsers to your webpage!

You can sniff for WPA-Handshakes and even Half-WPA-Handshakes for ap-less password cracking!

<b>Integrated Man-In-The-Middle</b>

An Evil-Twin is nothing without a proper MITM arsenal!

The framework uses the mitmproxy library (https://mitmproxy.org/) to create a local proxy capable of custom Level3 packet manipulation! Some fun ones have already been implemented such as beef hook injection into someones webpage, download content replacement with other files (idea stolen from the Wi-Fi Pumpkin Project: https://github.com/P0cL4bs/WiFi-Pumpkin/). And my favorite: .exe file infection with PEInjector. PEInjector does a great job by seemlessly injecting a payload into an exe file without changing its size while at the same time obfuscating the payload to pass AV software.

You can easily contribute and/or make your own custom MITM packet manipulation and add it to the framework. More information will be in the wiki.

<b>Wi-Fi Reconossaince</b>

The framework is able to sniff for access points, probe requests and responses and associating them to Wi-Fi clients. You can also log all of this information.

<b>Packet Injection</b>

Packet Sniffing and Injection is all done via Scapy. This makes it possible to contribute with any feature that involves packet sniffing and custom packet assembly and injection.

For now the only packet injection feature is deauthentication packets since it is a nice thing to have when trying to catch WPA-Handshakes.

<b>Spawners</b>

Spawners are a great and easy way to use your custom tools in conjunction with the framework. Some tools have already been added since they make a lot of sense: Ettercap, Beef, MITMFramework and SSLStrip.

You can easily add your own, more information will be in the wiki.

# Installation

Clone the project and run the setup file:

> ./setup

One of the MITM Plugins relies on peinjector service, this has to be installed manually following the instructions of the project.

> https://github.com/JonDoNym/peinjector

# Usage

First enter the ETF Console interface as root:

> ./etfconsole

For now there only is a console interface that is very easy to use and has tab completion!
The whole thing will work according to the etf.conf file.
You can view and change all configurations via de console, just type:

> config \<press double tab>

to list the modules available for configuration.
While working on the console type:

> listargs

to view the available parameters (here you can check if configurations are OK), then type:

> set \<parameter> \<value>

to change it.

If a parameter is (dict) it means it is another configurable module within.

To start an access point make sure you have it configured correctly, type:

> config airhost

check if everything is OK (use listargs)

> config aplauncher

check if everything is OK (use listargs)

> config dnsmasqhandler

check if everything is OK and start the access point

> start airhost

You can also configure an access point by copying one that is nearby.
Start scanning:

> config airscanner

check if everything is OK (use listargs)

> start airscanner

... wait ...

> show sniffed_aps

This lists the sniffed access points with their ids

> copy ap \<id>

OR

> show sniffed_probes

> copy probe \<id>

Then start the fake access point

> start airhost


You can deauthenticate others from their network while running the acces point.
To add access points or clients to be deauthenticated type:

> show sniffed_aps

> add aps \<filter_string>

The filter_string follows an easy syntax, it goes:

\<filter_keyword> \<filter_args>

The args can be any of the column names listed in the table.
The filter keywords are 'where' for inclusive filtering or 'only' for exclusive filtering, examples:

This will add the access point whose id is 5 to the deauthentication list (this is adding a single and specific AP):

> add aps where id = 5

This will add the access point whose ssid is 'StarbucksWifi' to the deauthentication list:

> add aps where ssid = StarbucksWifi

This will add the access point whose encryption type has 'wpa' OR 'opn' to the deauthentication list:

> add aps where crypto = wpa, crypto = opn

This will add the access point whose ssid id 'freewifi' AND is on channel 6 to the deauthentication list:

> add aps only ssid = freewifi, channel = 6

You can use the same interface for injecting packets while running the fake access point.
You can check and set configurations with:

> config airinjector

> listargs

After all that run the Injector (which by default performs Deauthentication attack):

> start airinjector

Same can be done when deleting from the deauth list with the 'del' command.
The 'show' command can also be followed by a filter string


Contributors can program Plugins in python either for the airscanner or airhost or airdeauthor.
Contributors can also code MITM scripts for mitmproxy.
