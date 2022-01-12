#!/usr/bin/env python3

__author__ = "Gary Choi"
__project__= "Graduate Research Project"
__name__="WAAT"

import subprocess
import re
import csv
import os
import time
import shutil
from datetime import datetime

wireless_interface = []

def banner():
    print ("\n+------------------------------------------+")
    print ("|     _     _  _______  _______  _______     |")
    print ("|    | | _ | ||   _   ||   _   ||       |    |")
    print ("|    | || || ||  |_|  ||  |_|  ||_     _|    |")
    print ("|    |       ||       ||       |  |   |      |")
    print ("|    |       ||       ||       |  |   |      |")
    print ("|    |   _   ||   _   ||   _   |  |   |      |")
    print ("|    |__| |__||__| |__||__| |__|  |___|      |")
    print ("|                                            |")
    print ("| Coded by Gary Choi                         |")
    print ("| Repo: https://github.com/garychd214/WAAT   |")
    print ("+--------------------------------------------+\n")

def clear():
    _ = subprocess.call('clear')

clear()
banner()

# If script doesn't run with super user privileges, break the script
if not 'SUDO_UID' in os.environ.keys():
    print("Please run the script with sudo")
    exit()

# Check if aircrack-ng package is installed
res = subprocess.run('dpkg-query -l aircrack-ng', shell=True)
if(res.returncode != 0):
    print("Please install aircrack-ng")
    exit()
else:
    clear()
    banner()

# wlan interface finder
wlan_finder = re.compile("^wlan[0-9]+")
# Find all wireless interface from iwconfig command
wlan_int_list = wlan_finder.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())

# Debug Check Wlan list
print(wlan_int_list)