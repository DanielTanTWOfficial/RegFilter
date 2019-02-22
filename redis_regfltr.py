
# 	Jun Kang 5/22/2018
# 	The main purpose of this Python file is to check and retrieve data that is being logged into Redis and convert any hex value 
#     of hostname and activename to readable format so that it can be printed and written out onto an external CSV file. The CSV will 
#     be created and written in the same location of the Python file itself. Before using this file, ensure that Redis, Python and the
#     setup of Redis Python is successfully setup on the computer. 
# 	More information about how to setup and use the script can be found in the documentation or the related links below.
#     https://redislabs.com/lp/python-redis/ (Setup of Redis Python)
#     https://github.com/rgl/redis/downloads (Setup for Redis Windows)
	
# 	Possible areas for improvement:
# 	2. Ability to filter the type of operation which the user want to write to the log file. (Flexibility)
	
# 	Possible solution that may work:
# 	2. Currently, the Python script writes out all the data from the 13 different types of operation into the external CSV. We can
#     make things more flexibility by possibly enabling the user to choose the type of operation to retrieve and write into the external
#     CSV file. This can possibly be done by two ways, either by allow user to key in the input into the Python console or the most tedious
#     and business aspect of the project is to create an user interface for the front end aspect of the project so that users can easily 
#     retrieve, see and filter the data out from Redis.
        
        
# 	The first part of possible area of improvement and its possible solution can be found in the Windows Registry Filter Driver(Log.c)


import redis

#establish Redis Py connection using your host, port and password
r = redis.Redis(
    host='localhost',
    port=6379,
    password='')


import string
import codecs

import csv

#opening the csv file, if do not exist, it will create the csv file
with open('regfltrLog.csv', 'w', newline='') as csvfile:
    #allow you to write into the CSV file directly
    filewriter = csv.writer(csvfile, delimiter=',',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)

    #if Redis list is empty, print no data is logged to console and write it to the csv file
    if (r.llen('regfltrList') == 0):
        filewriter.writerow(["No data is logged"])
        print("No data is logged")

    #if Redis list is  not empty, write out the data that is logged.
    else:
        # writing the header
        filewriter.writerow(
            ['Message ID', 'Timestamp', 'Operation Type', 'User ID', 'Username', 'Process Name', 'Process ID',
             'Value Name (OPT)', 'Hostname', 'Active Name', 'Registry Path'])
        #for loop through the list in the Redis
        for i in range(0, r.llen('regfltrList')):
            splitedWord = r.lindex('regfltrList', i).decode("utf-8").replace('\x00','').split(", ")
            ii = 0
            while ii < len(splitedWord):
                # decode hex value for the value in the [8] and [9] position of the array (hostname and activename)
                if (ii == 8 or ii == 9):
                    #check for hex encoding
                    if (all(c in string.hexdigits for c in splitedWord[ii])):
                        decodedHostName = codecs.decode(splitedWord[ii], "hex").decode("utf-8").replace('\x00','')
                        location = splitedWord.index(splitedWord[ii])
                        splitedWord.remove(splitedWord[ii])
                        splitedWord.insert(location, decodedHostName)
                ii += 1

            filewriter.writerow(splitedWord)
            print(splitedWord)


