
import sys
import os           #os module, used for file and path handling
import re
import getopt
import json         #Json module
import urllib2
import urllib
#import postfile     #postfile module
import requests     #requests module


def main(argv):#argv -> argument vector (a one-dimensional array of strings) that holds all the commandline arguments

    for arg in argv:
            _hash=re.findall("([a-fA-F\d]{30,64})", arg)
            if _hash:
                hsh=("%s" % (''.join(((_hash)))))
                print(hsh)
                hashScan()#Call the apis to scan given file
                #end of for


def hashScan():
        
    #scanning hashes

    url = "https://hashlookup.metadefender.com/v2/hash/BED12FDA073BB386B54700138FB47EEA"

    headers = {'apikey': "b3eba1d13814f0ba795840afb01e76f4"}

    response = requests.request("GET", url, headers=headers)

    print(response.text)


if __name__ == "__main__":
    main(sys.argv[1:])  

