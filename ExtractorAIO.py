"""
Author : Saket Upadhyay
Android Permission Extraction and Database Creation

26 Sept. 2019
"""
from os import system as sys
import os, time
import xml.etree.ElementTree as ET
import numpy as np
import csv



# FUNCTION TO MERGE FOUND PERMISSIONS TO DEFAULT PERMISSION LIST TO CREATE COMPRIHENSIVE PERMISSION LIST
def PermListUpdater():
    updateList = []
    defaultList = []
    with open('./PermList/UpdatePermList.txt') as updateFile:
        updatedata = updateFile.read()
        updateList = updatedata.split('\n')
    updateList.pop()
    with open('./PermList/DefaultPermList.txt') as defaultFile:
        defaultdata = defaultFile.read()
        defaultList = defaultdata.split('\n')
    defaultList.pop()

    newList=defaultList+list(set(updateList) - set(defaultList))

    with open('./PermList/UpdatedPermList.txt', 'w') as dumpFile:
        for i in newList:
            dumpFile.write(i+'\n')


# FUNCTION TO CREATE .csv FILE TO STORE DATA FROM PERMISSION LIST SUPPLIED
def CSVFormatter():
    test_file=open("./PermList/UpdatedPermList.txt")
    data=test_file.read()
    test_file.close()

    permlist=data.split('\n')
    permlist.pop()

    csv_row_data=['NAME']  #ADD NAME COLUMN
    csv_row_data += permlist
    csv_row_data.append('CLASS') # ADD PERMISSION COLUMN 

    with open('data.csv','w') as csv_file:
        writer=csv.writer(csv_file)
        writer.writerow(csv_row_data)


#FUNCTION TO EXTRACT PERMISSIONS FROM APPLICATIONS TO CREATE A LIST
def Extract():
    DIRTYPE=["./MalwareAPK","./BenignAPK"]
    permCollection = set()


    for datastoredir in DIRTYPE:
        if datastoredir == "./MalwareAPK":          # FILTER APK TYPE TO AID IN LABEL GENERATION
            apktype="MALWARE"
        else:
            apktype="BENIGN"
        Flag=1
        TimeStamp = str(time.time())
        Jdax = "./Modules/jadx/bin/jadx"            # JADX MODULE PATH
        TargetApkPath = datastoredir
        ApkNameList = os.listdir(datastoredir)
        if len(ApkNameList) == int(0):
            Flag=0

        if Flag != int(0):
            ApkNameList.sort()
            TargetApkPath = datastoredir+"/"
            CurrentApk = 0

            for ApkName in ApkNameList:
                TargetApk = TargetApkPath + ApkName

                print("("+str(apktype)+")"+ " [" + str(CurrentApk + 1) + ' / ' + str(len(ApkNameList)) + "] --- "+ApkName,end="")
               
                sys(Jdax + " -d ./UnpackedApk/" + ApkName + TimeStamp + " " + TargetApk+ " >/dev/null" )        # USE JADX TO EXTRACT FILES FROM APK AND MAINFEST.XML
                UnpackedDir = "./UnpackedApk/" + ApkName + TimeStamp
                MainfestPath = UnpackedDir + "/resources/AndroidManifest.xml"
                try:
                    root = ET.parse(MainfestPath).getroot()
                    permissions = root.findall("uses-permission")

                    print("  SET STATUS :", end=' ')        # ADD NEW PERMISSION TO THE LIST
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


    with open("./PermList/UpdatePermList.txt", 'w') as file:        # SAVE LIST IN FILE.
        for i in permList:
            file.write(i + '\n')


#FUNCTION TO CREATE DATASET FROM EXISTING .csv FILE AND SUPPLIED APK FILES FOLDER.
def Bagger(datastoredir):
    if datastoredir == "./MalwareAPK":
        TYPE=1                        # TYPE SET TO DIFFERENTIATE MALWARE AND BENIGN IN DATASET WITH LABELS
        print("\n\t ** Extracting From Malware Samples ** \n\n")
    elif datastoredir =="./BenignAPK":
        TYPE=0
        print("\n\t ** Extracting From Benign Samples ** \n\n")
    TimeStamp = str(time.time())
    Flag=1

    Jdax = "./Modules/jadx/bin/jadx"
    TargetApkPath = datastoredir+"/"
    ApkNameList = os.listdir(datastoredir)
    if len(ApkNameList) == int(0):
        Flag=0

    if Flag != int(0):
        ApkNameList.sort()
        TotalApks = len(ApkNameList)
        CurrentApk = 0
        fieldnames=[]
        with open('data.csv') as csv_file:
            CSVREADER=csv.DictReader(csv_file)
            fieldnames=CSVREADER.fieldnames     #GET THE FIELD NAMES

        csv_master_dict=dict.fromkeys(fieldnames,0)


        for ApkName in ApkNameList:
            TargetApk = TargetApkPath + ApkName

            print(">[" + str(CurrentApk + 1) + ' / ' + str(TotalApks) + "] --- "+ApkName ,end=' ')
            print("\t.",end=' ')
            sys(Jdax + " -d ./UnpackedApk/" + ApkName + TimeStamp + " " + TargetApk + " >/dev/null")        #EXTRACT THE PERMISSIONS FROM THE APK FILES
            print(".",end=' ')

            UnpackedDir = "./UnpackedApk/" + ApkName + TimeStamp
            MainfestPath = UnpackedDir + "/resources/AndroidManifest.xml"

            try:
                root = ET.parse(MainfestPath).getroot()         # FORMAT DATA ROW 
                permissions = root.findall("uses-permission")
                csv_master_dict=dict.fromkeys(fieldnames,0)
                csv_master_dict['NAME']=ApkName
                csv_master_dict['CLASS']=TYPE
                for perm in permissions:
                    for att in perm.attrib:
                        permelement = perm.attrib[att]
                        csv_master_dict[permelement]=1
                sys("rm -f -R " + UnpackedDir)
                print(".", end=' ')
                with open('data.csv', 'a') as csv_dump:
                    CSVwriter = csv.DictWriter(csv_dump, fieldnames=fieldnames)
                    CSVwriter.writerow(csv_master_dict)         # SAVE DATA TO DATASET ROW BY ROW FOR EACH APPLICATION
                print(".")
            except Exception:
                print("EERRRROORR")
                pass
            CurrentApk += 1



# MAIN DRIVER FUNCTION 
def Main():
    sys("rm './PermList/UpdatePermList.txt' './PermList/UpdatePermList2.txt' './PermList/UpdatedPermList.txt'")  # TO CLEAN THE STRUCTURE BEFORE STARTING
    sys("rm -rf ./UnpackedApk/*")
    Malware_Directory_Name="./MalwareAPK"
    Benign_Directory_Name="./BenignAPK"
    sys("clear")
    print("\tANDROID PERMISSION BASED DATASET CREATOR FOR ML MODELS \n\tGIT : https://github.com/Saket-Upadhyay/Android-Permission-Extraction-and-Dataset-Creation-with-Python\n\n")
    print("Extracting Permissions\t[*---]")
    Extract()
    print("\n\nCreating Base Permission List\t[**--]")
    PermListUpdater()
    print("\n\nCreating Base Dataset\t[***-]")
    CSVFormatter()
    print("\n\nCreating Main Dataset\t[****]")
    Bagger(Benign_Directory_Name)
    Bagger(Malware_Directory_Name)
    print("\n## Cleaning Temp. Files")
    sys("rm -rf ./UnpackedApk/*")
    sys("rm './PermList/UpdatePermList.txt' './PermList/UpdatedPermList.txt'")
    print("\n\n ***************DONE*****************  \nSaved as data.csv")


if __name__ == '__main__':
    Main()
