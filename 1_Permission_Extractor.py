# Created by: Saket Upadhyay
# Created on: 09/08/19
# This script extracts Permissions from APKs in 'UploadApk' folder and list all the permissions used in list of apps in one file
# This will create base for CSV_formatter.py or PermListUpdater.py
#
from os import system as sys
import os, time
import xml.etree.ElementTree as ET
import threading
import numpy as np

permCollection = set()
TimeStamp = str(time.time())
# print(TimeStamp)
# JDAX LOCATION SET
Jdax = "./Modules/jadx/bin/jadx"
TargetApkPath = "./UploadApk/"
ApkNameList = os.listdir('./UploadApk')
ApkNameList.sort()
TotalApks = len(ApkNameList)




def Extract(apknamelistpassed,dumpfilename):
    TargetApkPath = "./UploadApk/"
    CurrentApk = 0
    for ApkName in apknamelistpassed:
        TargetApk = TargetApkPath + ApkName

        print(ApkName + " --- [" + str(CurrentApk + 1) + ' / ' + str(len(apknamelistpassed)) + "]")
        print("starting unpack")
        sys(Jdax + " -d ./UnpackedApk/" + ApkName + TimeStamp + " " + TargetApk + " >/dev/null")
        print("Unpacking Done !!")

        # UNPACK DIR LOCATION SET
        UnpackedDir = "./UnpackedApk/" + ApkName + TimeStamp
        MainfestPath = UnpackedDir + "/resources/AndroidManifest.xml"
        try:
            root = ET.parse(MainfestPath).getroot()
            permissions = root.findall("uses-permission")

            print("SET STATUS :", end=' ')
            for perm in permissions:
                for att in perm.attrib:
                    permelement = perm.attrib[att]

                    if permelement in permCollection:
                        print("0", end=' ')
                    else:
                        print("1", end=' ')
                        permCollection.add(permelement)

        except FileNotFoundError:
            print('Error')
            print(TargetApk)
            pass
        sys("rm -f -R " + UnpackedDir)
        print()
        CurrentApk += 1

    permList = list(permCollection)

    with open(dumpfilename, 'w') as file:
        for i in permList:
            file.write(i + '\n')


if __name__ == '__main__':
    Extract(ApkNameList,"permExtract.txt")


    print("Done")