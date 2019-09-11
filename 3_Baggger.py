# Created by: Saket Upadhyay
# Created on: 09/08/19
# This script will extract the permissions from APKs in UploadApk folder and then will compare them with the data.csv entries,
# ultimately compiling them all in the data file.

from os import system as sys
import os,csv,time
import xml.etree.ElementTree as ET

permCollection = set()
TimeStamp = str(time.time())
# print(TimeStamp)


# JDAX LOCATION SET
Jdax = "./Modules/jadx/bin/jadx"
TargetApkPath = "./UploadApk/"
ApkNameList = os.listdir('./UploadApk')
ApkNameList.sort()
TotalApks = len(ApkNameList)
CurrentApk = 0
#get field names
fieldnames=[]
with open('data.csv') as csv_file:
    CSVREADER=csv.DictReader(csv_file)
    fieldnames=CSVREADER.fieldnames

csv_master_dict=dict.fromkeys(fieldnames,0)


for ApkName in ApkNameList:
    TargetApk = TargetApkPath + ApkName

    print(ApkName + " \n--- [" + str(CurrentApk + 1) + ' / ' + str(TotalApks) + "]",end=' ')
    print("\tStarting unpack...",end=' ')
    sys(Jdax + " -d ./UnpackedApk/" + ApkName + TimeStamp + " " + TargetApk + " >/dev/null")
    print("\tUnpacking Done !!",end=' ')

    # UNPACK DIR LOCATION SET
    UnpackedDir = "./UnpackedApk/" + ApkName + TimeStamp
    MainfestPath = UnpackedDir + "/resources/AndroidManifest.xml"

    try:
        root = ET.parse(MainfestPath).getroot()
        permissions = root.findall("uses-permission")
        csv_master_dict=dict.fromkeys(fieldnames,0)
        csv_master_dict['NAME']=ApkName
        csv_master_dict['CLASS']="1"
        # 1 for malware
        # 0 for safe/ benign
        for perm in permissions:
            for att in perm.attrib:
                permelement = perm.attrib[att]
                csv_master_dict[permelement]=1
        sys("rm -f -R " + UnpackedDir)
        print("\tUpdating dataset...", end=' ')
        with open('data.csv', 'a') as csv_dump:
            CSVwriter = csv.DictWriter(csv_dump, fieldnames=fieldnames)
            CSVwriter.writerow(csv_master_dict)
        print("\tDataset Updated.")
    except Exception:
        print("EERRRROORR")
        pass
    CurrentApk += 1
