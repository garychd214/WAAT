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

def check(test_var):
    print(wireless_lists[test_var]['Privacy'])
    print(wireless_lists[test_var]['Cipher'])
    print(wireless_lists[test_var]['Evil_Twin_ind'])
    print(wireless_lists[test_var]['Encryption_ind'])
    print(wireless_lists[test_var]['Cipher_ind'])
    print(wireless_lists[test_var]['Alert'])

WAP_Broad = 0


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
# Checking Evil Twins
# Copy ESSID from the dictionary to List for comparison
    for index, item in enumerate(wireless_lists):
        comparing_lists.append(item['ESSID'])

# Comparing ESSIDs to find out the Evil Twin
for i in range(len(comparing_lists)):
	for j in range(len(comparing_lists)):
		if i != j:
			if comparing_lists[i] != " " and comparing_lists[i] == comparing_lists[j]:
				wireless_lists[i]['Evil_Twin_ind'] = "Red"

# Clear Comparing list for next checkup                
comparing_lists.clear()

# Checking Encryption (Privacy) and Cipher Security
# For Encryption: WEP and OPN is always Red, WPA is Red if Cipher is TKIP, but Amber if Cipher is AES (CCMP). WPA2 is Green
# For Cipher: TKIP or OPEN is always Red, AES (CCMP) is Green for WPA2 and Amber for WPA 
for i in range(len(wireless_lists)):
    if "WEP" in wireless_lists[i]['Privacy']:
        wireless_lists[i]['Encryption_ind'] = "Red"
		
    elif "WPA2" in wireless_lists[i]['Privacy']:
        if "TKIP" in wireless_lists[i]['Cipher']:
            wireless_lists[i]['Cipher_ind'] = "Red"
			        
    elif "WPA" in wireless_lists[i]['Privacy']:
        if "TKIP" in wireless_lists[i]['Cipher']:
            wireless_lists[i]['Encryption_ind'] = "Red"
            wireless_lists[i]['Cipher_ind'] = "Red"
        elif "AES" or "CCMP" in wireless_lists[i]['Cipher']:
            wireless_lists[i]['Encryption_ind'] = "Amber"
            wireless_lists[i]['Cipher_ind'] = "Amber"
			
    elif "OPN" in wireless_lists[i]['Privacy']:
        wireless_lists[i]['Encryption_ind'] = "Red"
        wireless_lists[i]['Cipher_ind'] = "Red"
        
    else:
        print("Index: ",i,", BSSID: ", wireless_lists[i]['BSSID'], " has Encryption/Chipher error")
		
# Set Alert.
for i in range(len(wireless_lists)):
    if wireless_lists[i]['Evil_Twin_ind'] == "Amber" or wireless_lists[i]['Cipher_ind'] == "Amber" or wireless_lists[i]['Cipher_ind'] == "Amber":
        if wireless_lists[i]['Alert'] == "Green":
            wireless_lists[i]['Alert'] = "Amber"
    elif wireless_lists[i]['Evil_Twin_ind'] == "Red" or wireless_lists[i]['Cipher_ind'] == "Red" or wireless_lists[i]['Cipher_ind'] == "Red":
        if wireless_lists[i]['Alert'] == "Green" or "Amber":
            wireless_lists[i]['Alert'] = "Red"
	
#print(comparing_lists)

check(1)
#print(wireless_lists)