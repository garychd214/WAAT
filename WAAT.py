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

def Encryption():
    print("Encryption")
    print("[Description]")
    print()
    print("Encryption is the process of converting traffic using the cipher.")
    print("There are no apparent physical borders in WLANs because it’s using radio waves. Therefore WLAN can be listened to by anyone within the range and potentially connect to other traffics. The encryption for WLAN keeps data private, so only the appropriate parties can understand the data.")
    print()
    print("[Risks]")
    print("Whenever encryption is cracked, the hacker could read the traffic that might contain the user’s credentials, PII, or even financial information and alter the traffic by performing a Man-in-the-Middle(MITM) attack. ")
    print()
    print("[Possible Damage]")
    print("There are indefinite damages that could happen to the user and/or the business. It could expose the user’s credentials for social media or email systems, leak sensitive information, or cause secondary damage such as uses for crimes like scams or fraud. Moreover, the hacker could perform a “Session Hijack” on your bank screen or PayPal and process financial transactions.")
    print()

def Cipher():
    print("Cipher")
    print("[Description]")
    print()
    print("Cipher is a method (algorithm) used for the encryption process.")
    print()
    print("[Risks]")
    print("If encryption is deciphered, the hacker can see all the traffic in cleartext. If there is SI in the traffic, a data leak could occur.")
    print()
    print("[Possible Damage]")
    print("There are indefinite damages that could happen to the user and/or the business. It could expose the user’s credentials for social media or email systems, leak sensitive information, or cause secondary damage such as uses for crimes like scams or fraud. ")
    print()

def Evil_Result(evil):
    if(evil == "_Red_"):
        print("Evil Twin\n[Risks] \nEvil twin attacks pose a significant cybersecurity risk for both end users and businesses. \n\n")
        print("[Description] \n\n An evil twin is a fraudulent Wi-Fi access point that appears to be legitimate but is set up to eavesdrop on wireless communications. \nThe evil twin is the wireless LAN equivalent of the phishing scam. \nThis type of attack may be used to steal the passwords of unsuspecting users, either by monitoring their connections or by phishing, which involves setting up a fraudulent web site and luring people there.")
        print("\n\n[Possible Damage] \n\n To USERS \n Hackers often use evil twin attacks to gain access to personal user data like login credentials, bank transactions and credit card information. This is especially dangerous for users who use the same username and password for multiple accounts, since the hacker could gain access to all of them by monitoring just one login attempt.")
        print("\n To Business \n If a user logs into their company’s portal while connected to an evil twin network, the hacker can gain access to the company website using the employee’s credentials. This poses a significant cybersecurity risk as hackers can then access company data or plant malware in the system.")
        print("\n\n[Suggestion] \n\n1. Disable auto-connect features in your devices \n If auto-connect features are on, the device will connect to the hacker device when the hacker attacks WAP.")
        print("2. Avoid using Sensitive information (Personal Identifiable Information, Financial information, Protected Health Information, etc.) \n Hacker could capture data you send.")
        print("3. Use VPN \nVPN encrypts your data on the Internet. (Ensure to use secure VPN service with strong encryption protocols)")

def Encryption_Result(encryption):
    if(encryption == "OPN"):
        print("Encryption is NOT SECURE / OPEN")
        Encryption()
        print("Encryption: OPEN")
        print("[Description]")
        print()
        print("There is no encryption in the traffic.")
        print()
        print("[Suggestion]")
        print("1. Utilize the Encryption.\n2. Avoid using Sensitive information (Personal Identifiable Information, Financial information, Protected Health Information, etc.) ")
        
    if(encryption == "WEP"):
        print("Encryption is weak / WEP")
        Encryption()
        print("Encryption: WEP")
        print("[Description]")
        print("In WEP authentication, a wireless device sends an authentication request to the access point, which will reply with a 64-bit or 128-bit challenge in cleartext. The client will sign that challenge with the shared secret key and send it back to the access point. The AP will decrypt the signed message using the same shared key as the client did and verify the challenge sent.")
        print("Because WEP uses 64-bit or 128-bit challenge to grant access, the hacker only needs to know the challenge code, not the actual password.")
        print()
        print("[Strength]")
        print("According to aircrack-ng documentation, 64-bit WEP can usually be cracked in less than 5 minutes (generally less than 60 seconds), and 128-bit usually takes 30 minutes to an hour. ")
        print("Also, the result from the article, “Vulnerability issues on research in WLAN encryption algorithms WEP WPA/WPA2 Personal,” took around a minute or two for 64-bit WEP and three to four minutes for 128-bit WEP.")
        print()
        print("[Suggestion]")
        print("1. Utilize better Encryption with Chipher.\n2. Avoid using Sensitive information (Personal Identifiable Information, Financial information, Protected Health Information, etc.) ")
        
    if(encryption == "WPA"):
        print("Encryption is weak / WPA")
        Encryption()
        print("Encryption: WPA")
        print("[Description]")
        print("WPA is the next version of encryption after WEP. It can provide security and ensure that only authorized users can access the WLAN. It uses improved RC4 data encryption that uses Temporary Key Integrity Protocol(TKIP) and 802.1x authentication. ")
        print("WPA is stronger than WEP, but it uses TKIP cipher, which is depreciated by WPA2-AES and vulnerable to MIC key recovery attacks, Chop-Chop Attack, etc.")
        print("However, WPA is compatible with the older software; users might require to use it.")
        print()
        print("[Strength]")
        print("WPA is way stronger than WEP, but there are multiple attacks for the TKIP cipher.")
        print()
        print("[Suggestion]")
        print("1. Upgrade to WPA2 after confirming all devices and software supports WPA2.\n2. Avoid using Sensitive information (Personal Identifiable Information, Financial information, Protected Health Information, etc.) ")

def Cipher_Result(cipher):
    if(cipher == "TKIP"):
        print("Cipher is Weak / TKIP")
        Cipher()
        print("Cipher: TKIP")
        print("[Description]")
        print("TKIP was developed to improve the security of WEP. TKIP wraps the WEP by adding extra code at the beginning and end of every data packet. It uses the same 4RC data encryption with new security characteristics such as per-packet key hashing, sequence counter, etc.")
        print()
        print("[Suggestion]")
        print("1. Use PSK cipher after confirming the compatibility of all devices and software.\n2. Avoid using Sensitive information (Personal Identifiable Information, Financial information, Protected Health Information, etc.) ")
        
    if(cipher == ""):
        print("There is no Cipher")
        Cipher()




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
            clear()
            banner()
            print()
            print("Scanning. Press Ctrl + C when you want to select wireless network you wish to check")
            print()
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
            wireless_lists[i]['Cipher_ind'] = "Amber"
			        
    elif "WPA" in wireless_lists[i]['Privacy']:
        if "TKIP" in wireless_lists[i]['Cipher']:
            wireless_lists[i]['Encryption_ind'] = "_Red_"
            wireless_lists[i]['Cipher_ind'] = "Amber"
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
    if wireless_lists[i]['Evil_Twin_ind'] == "Amber" or wireless_lists[i]['Encryption_ind'] == "Amber" or wireless_lists[i]['Cipher_ind'] == "Amber":
        if wireless_lists[i]['Alert'] == "Green":
            wireless_lists[i]['Alert'] = "Amber"
    elif wireless_lists[i]['Evil_Twin_ind'] == "_Red_" or wireless_lists[i]['Encryption_ind'] == "_Red_" or wireless_lists[i]['Cipher_ind'] == "_Red_":
        if wireless_lists[i]['Alert'] == "Green" or "Amber":
            wireless_lists[i]['Alert'] = "_Red_"

print("\n")


while True:
    choice = input("Please make choice you wish to Check\n")
    try:
        if wireless_lists[int(choice)]:
            break
    except IndexError:
        print("Please choose from above\n")
        
    except ValueError:
        print("Please enter index\n")
    
# page 1: Main page
# page 2: Evil Twin
# page 3: Privacy
# page 4: Cipher

# Defining Pages
def page1():
    clear()
    banner()
    print(f"Evil Twin: {wireless_lists[int(choice)]['Evil_Twin_ind']}")
    print(f"Encryption: {wireless_lists[int(choice)]['Encryption_ind']}")
    print(f"Cipher Twin: {wireless_lists[int(choice)]['Cipher_ind']}")
    print("press D for Next page")
    
def page2():
    clear()
    banner()
    Evil_Result(wireless_lists[int(choice)]['Evil_Twin_ind'])
    print("press A for Previous page or D for Next page")

def page3():
    clear()
    banner()
    Encryption_Result(wireless_lists[int(choice)]['Privacy'])
    print("press A for Previous page or D for Next page")
    
def page4():
    clear()
    banner()
    Cipher_Result(wireless_lists[int(choice)]['Cipher'])
    print("press A for Previous page")

# Page navigator
page = 1
clear()
banner()
page1()
if wireless_lists[int(choice)]['Evil_Twin_ind'] == "Green" and wireless_lists[int(choice)]['Encryption_ind'] == "Green" and wireless_lists[int(choice)]['Cipher_ind'] == "Green":
    print("Your Wireless Access Point is Secure!")
else:
    print("press A for Previous page or D for Next page")
    while True:
        Choice = input()
        if Choice != "a" and Choice != "A" and Choice != "d" and Choice != "D":
            print("invalid input")
            print("press A for Previous page or D for Next page")
        else:
            if Choice == "a" or Choice == "A":
                if page == 2:
                    page1()
                    page = 1
                    print()

                if page == 3:
                    if wireless_lists[int(choice)]['Evil_Twin_ind'] != "Green":
                        page2()
                        page = 2
                        print()
                    else:
                        page1()
                        page = 1
                        print()
                        
                if page == 4:
                    if wireless_lists[int(choice)]['Encryption_ind'] != "Green":
                        page3()
                        page = 3
                        print()
                    else:
                        if wireless_lists[int(choice)]['Evil_Twin_ind'] != "Green":
                            page2()
                            page = 2
                            print()
                        else:
                            page1()
                            page = 1
                            print()
            if Choice == "d" or Choice == "D":
                if page == 1:
                    if wireless_lists[int(choice)]['Evil_Twin_ind'] != "Green":
                        page2()
                        page = 2
                        print()
                    else:
                        if wireless_lists[int(choice)]['Encryption_ind'] != "Green":
                            page3()
                            page = 3
                            print()
                        else:
                            if wireless_lists[int(choice)]['Cipher_ind'] != "Green":
                                page4()
                                page = 4
                                print()
                            else:
                                print("End of the page!\n")

                if page == 2:
                    if wireless_lists[int(choice)]['Encryption_ind'] != "Green":
                        page3()
                        page = 3
                        print()
                    else:
                        if wireless_lists[int(choice)]['Cipher_ind'] != "Green":
                            page4()
                            page = 4
                            print()
                        else:
                            print("End of the page!\n")

                if page == 3:
                    if wireless_lists[int(choice)]['Cipher_ind'] != "Green":
                        page4()
                        page = 4
                        print()
                    else:
                        print("End of the page!\n")
