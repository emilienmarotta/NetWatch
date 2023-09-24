##### Future improvements #####
# Check if libraries are installed on the client machine
# Offline
# Log management
# UX/UI

###

import subprocess

def install_additional_modules () :
    requirementsPath = "requirements.txt"
    requiredModules = []

    with open(requirementsPath, "r") as requirementsFile :
        for line in requirementsFile : 
            requiredModules.append(line.split(">=")[0])

    print("The program requires the installation of additional modules: ")
    for module in requiredModules : print("> {}".format(module))
    installInput = input("Would you like to install them? (y/n) ")

    if installInput != "y" : 
        exit()

    requirementsLogPath = "Logs/modulesInstallation.log"

    with open(requirementsLogPath, "w") as requirementsLogFile :
        try :
            subprocess.run(["pip", "install", "-r", "./requirements.txt"], stdout=requirementsLogFile, stderr=requirementsLogFile, check = True)
        except Exception as e:
            print("Error")
            exit()

if __name__ == "__main__" :
    install_additional_modules()

import socket 
import asyncio
import csv
import ping3
import scapy.all as scapy
import time
import tqdm

# Function definition

def transform_list_type (list, type) :
    if type == int :
        return [int(element) for element in list]
    elif type == float : 
        return [float(element) for element in list]
    else : 
        return [str(element) for element in list]
        
def disassemble_address (address, splitter) :
    return address.split(splitter) 

def assemble_address (addressElements, splitter) : 
    currentType = type(addressElements[0])
    if currentType != str :
        addressElements = transform_list_type(addressElements, str)
    return splitter.join(addressElements)

async def send_ICMP_request (ipv4, results, progressionBar) :
    responseTime = await asyncio.to_thread(ping3.ping, ipv4, timeout = 3)
    if (responseTime is not False) & (responseTime is not None) :
        result = 1
    else :
        result = 0
    results.append((result, ipv4))
    progressionBar.update(1)

async def test_ip_addresses (listOfAddressesToTest) :
    results = []
    with tqdm.tqdm(total=len(listOfAddressesToTest), desc="Progression") as progressionBar:
        tasks = [send_ICMP_request(ipv4, results, progressionBar) for ipv4 in listOfAddressesToTest]
        await asyncio.gather(*tasks)
    return results

def sort_ip_address_asc (listOfAddresses) :
    sortedList = sorted(listOfAddresses, key = lambda x: tuple(map(int, x.split("."))))
    return sortedList

def get_mac_address (ipv4) :
    try :
        arp = scapy.ARP(pdst = ipv4)
        ethernet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") # Broadcast
        packet = ethernet/arp
        response = scapy.srp(packet, timeout = 5, verbose = False)[0]
        macAddress = response[0][1].hwsrc # MAC address extraction
        return macAddress.upper()
    except : 
        return "Unknown"

def copy_csv_file_data_in_variable (filePath) :
    variable = []
    with open(filePath, "r", newline = "", encoding = "utf-8") as csvFile :
        csvReader = csv.DictReader(csvFile)
        for line in csvReader :
            variable.append(line)
    return variable

def get_device_manufacturer (macAddressPrefix, ouiDatabase) :
    for line in ouiDatabase :
        if line["MacPrefix"] == macAddressPrefix :
            return line["VendorName"]
    return "Unknown"


# Main program

## Collect network information

### IP address identification

socket1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP connection
socket1.connect(("8.8.8.8", 80)) #8.8.8.8 = Google DNS server IPv4 address
ipv4 = socket1.getsockname()[0]
socket1.close()

### Netmask identification

"""
We use the separation of netmasks into 3 classes (A, B, C) mentioned in RFC 791. This method is obsolete and will be the subject of a future update of the program.
""" 
netmask = ""
ipv4BytesRaw = disassemble_address(ipv4, '.')
ipv4Bytes = transform_list_type(ipv4BytesRaw, int)
if 1 <= ipv4Bytes[0] <= 126 :
    netmask = "255.0.0.0" # Class A
elif 128 <= ipv4Bytes[0] <= 191 :
    netmask = "255.255.0.0" # Class B
else :
    netmask = "255.255.255.0" # Class C

## Retrieve each address to be tested

ipv4BytesRaw = disassemble_address(ipv4, '.')
ipv4Bytes = transform_list_type(ipv4BytesRaw, int)
ipv4ToTest = []

if netmask == "255.255.255.0" :
    for i in range (0, 255) :
        ipv4Bytes[3] = i
        currentIpToTest = assemble_address(ipv4Bytes, ".")
        if (currentIpToTest != ipv4) :
            ipv4ToTest.append(currentIpToTest)
elif netmask == "255.255.0.0" :
    for i in range (0, 255+1) :
        for j in range (0, 255) :
            ipv4Bytes[3] = j
            currentIpToTest = assemble_address(ipv4Bytes, ".")
            if (currentIpToTest != ipv4) :
                ipv4ToTest.append(currentIpToTest)
        ipv4Bytes[2] = i
else : 
    for i in range (0, 255+1) :
        for j in range (0, 255+1) :
            for k in range (0, 255) :
                ipv4Bytes[3] = k
                currentIpToTest = assemble_address(ipv4Bytes, ".")
                if (currentIpToTest != ipv4) :
                    ipv4ToTest.append(currentIpToTest)
            ipv4Bytes[2] = j
        ipv4Bytes[1] = i

## Retrieve ICMP requests results

icmpRequestsResults = asyncio.run(test_ip_addresses(ipv4ToTest))

## Get connected devices

connectedDevices = []
nbConnectedDevices = 0

for element in icmpRequestsResults : 
    if element[0] == 1 :
        connectedDevices.append(element[1]) # Add ip address

connectedDevices.append(ipv4) # Our IP address
nbConnectedDevices = len(connectedDevices) 

## Sort the list of connected devices

connectedDevices = sort_ip_address_asc(connectedDevices)

## Collect MAC address

macAddresses = []

for address in connectedDevices :
    macAddresses.append(get_mac_address(address))

## Use OUI-Database to retrieve device manufacturer information

### Copy OUI-Database in a variable

databasePath = "Ressources/mac-vendors-export.csv"
ouiDatabase = copy_csv_file_data_in_variable(databasePath)

### Extract MAC address prefixes

macAddressPrefixes = []

for macAddress in macAddresses :
    if macAddress != "Unknown" :
        macAddressPrefix = macAddress[:8]
        macAddressPrefixes.append(macAddressPrefix)
    else : 
        macAddressPrefixes.append("Unknown")

### Search for matches in the database

manufacturers = []

for macAddressPrefix in macAddressPrefixes :
    manufacturers.append(get_device_manufacturer(macAddressPrefix, ouiDatabase))

## Display

if (nbConnectedDevices > 1) :
    print("{} connected devices : ".format(nbConnectedDevices))
else :
    print("{} connected device : ".format(nbConnectedDevices))
print("IP address | MAC address | Manufacturer")
for index, device in enumerate(connectedDevices) : 
    if (device) == ipv4 :
        print("> {} | {} | {} (*)".format(device, macAddresses[index], manufacturers[index]))
    else : 
        print("> {} | {} | {}".format(device, macAddresses[index], manufacturers[index]))
    