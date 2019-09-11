# Created by: Saket Upadhyay
# Created on: 09/08/19
# This file will update the current permissions list for CSV formatter
additionalPerm = []
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

newList=defaultList + list(set(updateList) - set(defaultList))
with open('./PermList/UpdatedPermList.txt', 'w') as dumpFile:
    for i in newList:
        dumpFile.write(i+'\n')

