# Created by: Saket Upadhyay
# Created on: 09/08/19
# This scrip creates base for classifier by creating a template csv with the information and all the
# permissions found by the previous scripts
import csv

test_file=open("./PermList/UpdatedPermList.txt")

data=test_file.read()
test_file.close()

permlist=data.split('\n')
permlist.pop()

csv_row_data=['NAME']
csv_row_data += permlist
csv_row_data.append('CLASS')

with open('data.csv','w') as csv_file:
    writer=csv.writer(csv_file)
    writer.writerow(csv_row_data)

