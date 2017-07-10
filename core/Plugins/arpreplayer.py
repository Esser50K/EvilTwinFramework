# -*- coding: utf-8 -*-
"""
This plugin will launch a full arp replay attack on a WEP network
"""
import os, traceback
from pyric import pyw as pyw
from plugin import AirScannerPlugin
from AuxiliaryModules.packet import Beacon
from scapy.all import sniff
from utils.networkmanager import NetworkCard
from utils.utils import NetUtils
from threading import Thread
from time import sleep


class ARPReplayer(AirScannerPlugin):

	def __init__(self):
		super(ARPReplayer, self).__init__("arpreplayer")
		