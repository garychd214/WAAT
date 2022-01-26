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
comparing_lists = []

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

# Discover access points and output to WAP_list-01.csv
discover_access_points = subprocess.Popen(["sudo", "airodump-ng","-w" ,"WAP_list","--write-interval", "1","--output-format", "csv", wlan_using + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Check if target WAP broadcast ESSID
clear()
banner()
while True:
    WAP_Broad = input("Does target WAP broadcast ESSID? (no for 0, yes for 1) \n")
    try:
        if int(WAP_Broad) == "0" or int(WAP_Broad) == "1":
            break
    except:
        print("Invalid input, please try again")
        
# Load csv file and dump it to list
try:
    while True:
        for file_name in os.listdir():
            fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
            if ".csv" in file_name:
                with open(file_name) as csv_h:
                    csv_h.seek(0)
                    # Adding Encryption (security) indicator, Cipher (security) indicator, (Security) alert column
                    csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames + ['Evil_Twin_ind']+ ['Encryption_ind'] + ['Cipher_ind'] + ['Alert'])
                    for row in csv_reader:
                        if row["BSSID"] == "BSSID":
                            pass
                        elif row["BSSID"] == "Station MAC":
                            break
                        elif Checking_Bssid(row["BSSID"], wireless_lists):
                            row["Evil_Twin_ind"] = "Green"
                            row["Encryption_ind"] = "Green"
                            row["Cipher_ind"] = "Green"
                            row["Alert"] = "Green"
                            wireless_lists.append(row)

            # Wireless Access Point Broadcasting
            if(WAP_Broad == "1"):
                clear()
                print("Scanning. Press Ctrl + C when you want to select wireless network you wish to check \n")
                # showing only ESSID
                print("No ||\tESSID                         |")
                print("___||\t______________________________|")
                for index, item in enumerate(wireless_lists):
                    print(f"{index}\t{item['ESSID']}")
            # Wireless Access Point NOT Broadcasting
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
    # Rocever Wlan Interface
    wlan_stop_monitoring_mode = subprocess.run(["sudo", "airmon-ng", "stop", wlan_using + "mon"])
    start_Network_manager = subprocess.run(["sudo", "systemctl", "start", "NetworkManager"])

# Checking Evil Twins
# Copy ESSID from the dictionary to List for comparison
for index, item in enumerate(wireless_lists):
    comparing_lists.append(item['ESSID'])

# Comparing ESSIDs to find out the Evil Twin
for i in range(len(comparing_lists)):
	for j in range(len(comparing_lists)):
		if i != j:
			if comparing_lists[i] != " " and comparing_lists[i] == comparing_lists[j]:
				wireless_lists[i]['Evil_Twin_ind'] = "_Red_"

# Clear Comparing list for next checkup                
comparing_lists.clear()

# Checking Encryption (Privacy) and Cipher Security
# For Encryption: WEP and OPN is always Red, WPA is Red if Cipher is TKIP, but Amber if Cipher is AES (CCMP). WPA2 is Green
# For Cipher: TKIP or OPEN is always Red, AES (CCMP) is Green for WPA2 and Amber for WPA 
for i in range(len(wireless_lists)):
    if "WEP" in wireless_lists[i]['Privacy']:
        wireless_lists[i]['Encryption_ind'] = "_Red_"
		
    elif "WPA2" in wireless_lists[i]['Privacy']:
        if "TKIP" in wireless_lists[i]['Cipher']:
            wireless_lists[i]['Cipher_ind'] = "_Red_"
			        
    elif "WPA" in wireless_lists[i]['Privacy']:
        if "TKIP" in wireless_lists[i]['Cipher']:
            wireless_lists[i]['Encryption_ind'] = "_Red_"
            wireless_lists[i]['Cipher_ind'] = "_Red_"
        elif "AES" or "CCMP" in wireless_lists[i]['Cipher']:
            wireless_lists[i]['Encryption_ind'] = "Amber"
            wireless_lists[i]['Cipher_ind'] = "Amber"
			
    elif "OPN" in wireless_lists[i]['Privacy']:
        wireless_lists[i]['Encryption_ind'] = "_Red_"
        wireless_lists[i]['Cipher_ind'] = "_Red_"
        
    else:
        print("Index: ",i,", BSSID: ", wireless_lists[i]['BSSID'], " has Encryption/Chipher error")
		
# Set Alert.
for i in range(len(wireless_lists)):
    if wireless_lists[i]['Evil_Twin_ind'] == "Amber" or wireless_lists[i]['Privacy'] == "Amber" or wireless_lists[i]['Cipher_ind'] == "Amber":
        if wireless_lists[i]['Alert'] == "Green":
            wireless_lists[i]['Alert'] = "Amber"
    elif wireless_lists[i]['Evil_Twin_ind'] == "_Red_" or wireless_lists[i]['Privacy'] == "_Red_" or wireless_lists[i]['Cipher_ind'] == "_Red_":
        if wireless_lists[i]['Alert'] == "Green" or "Amber":
            wireless_lists[i]['Alert'] = "_Red_"

print("\n")


user_stop_ind = False

while user_stop_ind == False:
    while True:
        choice = input("Please make choice you wish to Check")
        try:
            if wireless_lists[int(choice)]:
                break
        except:
            print("Invalid Input. \n Please try again. \n")
    
    print(wireless_lists[int(choice)]['BSSID'], "\n \n")
    print("|____EvilTwin____|\t___Encryption___|\t_____Cipher_____|")
    print(f"|_____{wireless_lists[int(choice)]['Evil_Twin_ind']}_____|\t_____{wireless_lists[int(choice)]['Privacy']}_____|\t_____{wireless_lists[int(choice)]['Cipher_ind']}_____")
    