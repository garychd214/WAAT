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

wireless_lists = []
evaluated_list = []

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
    
def backup_old_csv():
    for file_name in os.listdir():
        # if old csv found, move it to backup folder
        if ".csv" in file_name:
            print("Old csv file found, it will be moved to backup folder")
            directory = os.getcwd()
            try:
                # We make a new directory called /backup
                os.mkdir(directory + "/backup/")
            except:
                print("Backup folder exists.")
            # Create a timestamp
            timestamp = datetime.now()
            shutil.move(file_name, directory + "/backup/" + file_name + "-" + str(timestamp))

def Checking_Bssid(bssid, lst):
    check_status = True
    # If no ESSIDs in list add the row
    if len(lst) == 0:
        return check_status

    # This will only run if there are wireless access points in the list.
    for item in lst:
        # If True don't add to list. False will add it to list
        if bssid in item["BSSID"]:
            check_status = False
    return check_status


clear()
banner()

## Initial Checkup, 
# 1. Check if it's running wiht sudo.
# 2. Check if aircrack-ng package is installed.

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

## Debug Check Wlan list
# print(wlan_int_list)

# if no wlan found, print msg and exit
if len(wlan_int_list) == 0:
    print("No WiFi Adapter Found in the system")
    exit()

# Show available WiFi interfaces
clear()
banner()
print("WiFi Adapter List: ")
print("[index] - [item]")
for index, item in enumerate(wlan_int_list):
    print(f"{index} - {item}")

# Ask for selection
while True:
    wlan_select = input("Please enter index number of the WiFi adpator you wish to use \n")
    try:
        if wlan_int_list[int(wlan_select)]:
            break
    except:
        print("Please select from the list")

# wlan_using will be the wlan adpater for use
wlan_using = wlan_int_list[int(wlan_select)]

# run command to kill all the conflict processes to switch to monitoring mode
kill_confilict_processes =  subprocess.run(["sudo", "airmon-ng", "check", "kill"])

# run command to switch wlan to monitoring more
wlan_monitoring_mode = subprocess.run(["sudo", "airmon-ng", "start", wlan_using])

#before creating csv file, move csv file to the backup folder
backup_old_csv()

# Discover access points
discover_access_points = subprocess.Popen(["sudo", "airodump-ng","-w" ,"file","--write-interval", "1","--output-format", "csv", wlan_using + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Check if target WAP broadcast ESSID
clear()
banner()
while True:
    WAP_Broad = input("Does target WAP broadcast ESSID? (no for 0, yes for 1) \n")
    try:
        if WAP_Broad == "0" or WAP_Broad == "1":
            break;
    except:
        print("Invalid input, please try again")
        
#create csv file and dump it
default_ind = 'Green'
try:
    while True:
        for file_name in os.listdir():
            fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key', 'Encryption_ind', 'Cipher_ind', 'alert']
            if ".csv" in file_name:
                with open(file_name) as csv_h:
                    csv_h.seek(0)
                    csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                    for row in csv_reader:
                        if row["BSSID"] == "BSSID":
                            pass
                        elif row["BSSID"] == "Station MAC":
                            break
                        elif Checking_Bssid(row["BSSID"], wireless_lists):
                            wireless_lists.append(row)
                            """
							# Defualt Encryption_ind = green
							wireless_lists.append(default_ind)
							# Defualt Cipher_ind = green
                            wireless_lists.append(default_ind)
							# Defualt alert = green
                            wireless_lists.append(default_ind)
                            
                            if item['Privacy'] == "WEP" or item['Privacy'] == "WPA" or item['Privacy'] == "OPN":
                                item['alert'] == "RED"
                                item['encryption_ind'] == "Red"
                            if item['Cipher'] == "TKIP" or item['Cipher'] == "":
                                item['alert'] == "RED"
                                item['Cipher_ind'] == "RED"
							"""
            if(WAP_Broad == "1"):
                clear()
                print("Scanning. Press Ctrl + C when you want to select wireless network you wish to check \n")
                # showing only ESSID
                print("No ||\tESSID                         |")
                print("___||\t______________________________|")
                for index, item in enumerate(wireless_lists):
                    print(f"{index}\t{item['ESSID']}")
            if(WAP_Broad == "0"):
                clear()
                print("Scanning. Press Ctrl + C when you want to select wireless network you wish to check \n")
                # showing only ESSID
                print("No |\tBSSID              |\tID_length|\tESSID                         |")
                print("___|\t___________________|\t_________|\t______________________________|")
                for index, item in enumerate(wireless_lists):
                    print(f"{index}\t{item['BSSID']}\t{item['ID_length'].strip()}\t\t{item['ESSID']}")
                
        # The script sleep for 1 second before loading the updated list.
        time.sleep(1)
        
except KeyboardInterrupt:
    print("\Please enter index number of the access point")