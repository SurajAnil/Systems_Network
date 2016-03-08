#!/usr/bin/python


"""threatintel.py: This project is designed to provide information on Indicators of
compromise artifacts from various sources including public apis and honeypot.json
(sample dataset from a public honeypot that records various security events.),
parse it based on the type (Attacker IP, Victim IP, Port, Connection Type, Source,
Timestamp, etc). The program basically accepts Indicators Of Compromise (IOC)
(IP address, port, source, domain, URL) as arguments to the program and to look up all
information related to the IOC(s) and provide the information in an user-friendly fashion. """

__author__      = "Suraj Bennur"
__version__     = "1.0"
__email__       = "sbennur@outlook.com"



import sys
import os           #os module, used for file and path handling
import re
import getopt
import json         #Json module
import urllib2
import urllib
import requests
import postfile     #postfile module
import requests     #requests module

"""Main method"""
def main(argv):#argv -> argument vector (a one-dimensional array of strings) that holds all the commandline arguments

    
                            
    #capturing URL addresses
    for arg in argv:
        url_list=((re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', arg)))#regex to match url pattern

        if (url_list):
            u=("%s" % (''.join(((url_list)))))#u -> strip the url from its sublist form i.e. ['http:google.com'] -> http://google.com
            _url_encoded=urllib.quote_plus(u)
            urlScan(u, _url_encoded)

    """Search our local Honeypot -> honeypot.json"""
    try:
        for arg in argv:#iterate over each cmd line argument
            ipaddr=((re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}', arg)))#regex for ip addresses

                           
            #search for ip addresses
            if (ipaddr):#if we get the ip address as a cmd line argument, then strip the ip from its sublist form.
                _ip=("%s" % (''.join(((ipaddr)))))

                #Search the honeypot.json
                print('+++++++++++++++++++++++++++++++++++++++++')
                print('+\tScanning the HONEYPOT file       +')    
                print('+++++++++++++++++++++++++++++++++++++++++')
                print('Querying the honeypot.json for more information, please wait...\n')


                #Open the honeypot.json file to look for  information
                with open('/home/suraj/Desktop/honeypot.json') as f: 

                    for line in f:# Load each line from file one at a time
                    
                        data=json.loads(line)

                        #Let pload contain the "payload" of each line in honeypot.json
                        pload=json.loads(data['payload'])

                        try: #Try
                            if _ip == pload.get('victimIP'):#check if given ip is compromised 
                                print("Information for Victim IP "+_ip+":\nAttacker IP:"+pload.get('attackerIP'))
                                print("Source: HoneyPot")
                                print("Connection Type: %s" %(pload.get('connectionType')))
                                print("Attacker Port: %s" %(pload.get('attackerPort')))
                                #end of if
                                
                            if _ip == pload.get('attackerIP'):#if given ip is attacker, display victim details 
                                print("Information for attacker IP "+_ip+":\nVictim IP:"+pload['victimIP'])
                                print("Source: HoneyPot")
                                print("Connection Type: %s" %(pload.get('connectionType')))
                                print("Victim Port: %s" %(pload.get('victimPort')))
                                #end of if
                                 
                            
                        except Exception as e:#catch block
                            print(str(e))#Catch any exception


                #Call the apis method to scan given ip address
                ipAddressScan(_ip)
                #end of for
                
    except Exception as e:
        print(str(e))


    #File checking
     
    for arg in argv:
        if os.path.isfile(arg):#if cmd line argument contains the ip address, then capture it
            fname=arg#store the file path in "fname"
            fileScan(fname)#Call the apis to scan given file
            #end of for

        
               



#Method for ip address scan
def ipAddressScan(_ip):
    print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    print("+\t\tSCANNING IP ADDRESSES using API          +")                  
    print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    
    #Starts here
    #GET resource, performs ip check using isc sans api
            
    #print(_ip)
    print('\n-----------------------------------------------\n-Scanning IP address from ISC SANS, please wait...')
    print('-----------------------------------------------\n')
    print('\nQuerying ISC SANS database for the IP ADDRESS %s, please wait...' %(_ip))
    urlisc = 'https://isc.sans.edu/api/ip/'+_ip+'?json'#("%s" % ('\t'.join(_ip)))
    
    #print("Please wait while we retrieve your data... \n")
    try: #Try block
        r = requests.get(urlisc)#receive the reports from the site
        d1=json.loads(r.text)#load the reports into a readable format
        print('\nInformation for the IP ADDRESS %s is as follows:' %(_ip))
        print("Count: %s" %(d1.get('ip',{}).get('count',{})))
        print("AsCountry: %s" %(d1.get('ip',{}).get('ascountry',{})))
        print("MaxRisk: %s" %(d1.get('ip',{}).get('maxrisk',{})))
        print("AsName: %s" %(d1.get('ip',{}).get('asname',{})))


                  
    except Exception as e: #Exception-catch block
            
        print(str(e))
        print("error in fetching : moving forward..")

            
    print("\nPlease wait, now querying virus total...\n")
    print('-----------------------------------------------')

    
    #scanning ip from virustotal
    try:
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'#url to scan and retrieve IP reports
        parameters = {'ip': _ip, 'apikey': '0c940f8ea73da597250d22c1a5bac45a20d3413a38862f0cf60166aea9b8a3c7'}#Parameters to send along with IP
        response_ip = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
        response_ip_json = json.loads(response_ip)#load it into json module

        #print the necessary information
        print ('Information is as follows:')
        print ("Country: %s" %(response_ip_json.get("country",{})))
        print ("Response Code: %s" %(response_ip_json.get("response_code",{})))
        print ("Verbose Message: %s" %(response_ip_json.get("verbose_msg",{})))
        print('\n')
    except:
        print("Something's not right.. moving on")


#Method for file scan   
def fileScan(fname):

    print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    print("+\t\tSCANNING FILES                          +")
    print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++')


    #sending files VirusTotal
    
    #apikey='0c940f8ea73da597250d22c1a5bac45a20d3413a38862f0cf60166aea9b8a3c7'

    
    host = "www.virustotal.com"#host of the file scan provider "http://virustotal.com"
    selector = "https://www.virustotal.com/vtapi/v2/file/scan"
    fields = [("apikey", "0c940f8ea73da597250d22c1a5bac45a20d3413a38862f0cf60166aea9b8a3c7")]
    file_to_send = open(fname, "rb").read()
    files = [("file", fname, file_to_send)]
    resp = postfile.post_multipart(host, selector, fields, files)#send files and other parameters as a POST request
    resp_json=(json.loads(resp))#Parse the json response using json module
    resource=(resp_json['resource'])

    #Retreiving file reports VirusTotal

    url = "https://www.virustotal.com/vtapi/v2/file/report"#retrieve the information from the url
    parameters = {"resource": resource, "apikey": "0c940f8ea73da597250d22c1a5bac45a20d3413a38862f0cf60166aea9b8a3c7"}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    reports_json=json.loads(response.read())#load it into json module to extract response


    #print the reports
    print("If your file is infected, the below reports would indicate:")
    print("Report from nProtect: %s" %(reports_json.get("scans", {}).get("nProtect", {}).get("result")))
    print("Report from CMC: %s" %(reports_json.get("scans", {}).get("CMC", {}).get("result")))
    print("Report from CAT-QuickHeal: %s" %(reports_json.get("scans", {}).get("CAT-QuickHeal", {}).get("result")))
    print("Report from AlYac: %s" %(reports_json.get("scans", {}).get("ALYac", {}).get("result")))
    print("Report from Malwarebytes: %s"%(reports_json.get("scans", {}).get("Malwarebytes", {}).get("result")))
    print("Report from K7AntiVirus: %s" %(reports_json.get("scans", {}).get("K7AntiVirus", {}).get("result")))
    print("Report from Alibaba: %s" %(reports_json.get("scans", {}).get("Alibaba", {}).get("result")))
    print("Report from Symantec: %s" %(reports_json.get("scans", {}).get("Symantec", {}).get("result")))
    print("Report from Avast: %s"%(reports_json.get("scans", {}).get("Avast", {}).get("result")))



    #Add a file to scan Malwr.com
    print('\n')
    print('sending file to scan malwr.com...')
    payload = {'api_key': 'dbb36411f71d4497ba521b8211cbecc5', 'shared': 'yes', 'file': fname}#populate the playload with the necessary information
    r = requests.post("https://malwr.com/api/analysis/add/", data=payload)
    print(r.text)#load it into a readable format
    print('\n')

    

    


#Method to scan URLs
def urlScan(u, _url_encoded):
    print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    print("+\t\tSCANNING URLS                           +")
    print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    #Sending and scanning URLs VirusTotal
    url = "https://www.virustotal.com/vtapi/v2/url/scan"#send information to virustotal
    parameters_url_scan = {"url": u, "apikey": "0c940f8ea73da597250d22c1a5bac45a20d3413a38862f0cf60166aea9b8a3c7"}
    data_url_scan = urllib.urlencode(parameters_url_scan)
    req_url_scan = urllib2.Request(url, data_url_scan)
    response_url_scan = urllib2.urlopen(req_url_scan)
    #send_url_response = json.loads(response_url_scan.read())
    print('\n-----------------------------------------------\n-Scanning URL from VirusTotal, please wait...')
    print('-----------------------------------------------')
    print('Querying VirusTotal database for the site %s, please wait...\n' %(u))

    #retrieving url scan reports
    #apikey='0c940f8ea73da597250d22c1a5bac45a20d3413a38862f0cf60166aea9b8a3c7'
    url_scan = "https://www.virustotal.com/vtapi/v2/url/report"#receive from virustotal
    parameters = {"resource": u, "apikey": "0c940f8ea73da597250d22c1a5bac45a20d3413a38862f0cf60166aea9b8a3c7"}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url_scan, data)
    url_report_response = urllib2.urlopen(req)
    url_report=(url_report_response.read())
    url_report_json=(json.loads(url_report))#load to json module
    #print((url_report_json))
    print("The url -> %s: " %(url_report_json.get('url',{})))
    print("Positives %s: " %(url_report_json.get('positives',{})))
    print("Reports from Avira: %s" %(url_report_json.get('scans', {}).get('Avira').get('result')))
    print("Reports from MalwareDomainList: %s" %(url_report_json.get('scans', {}).get('MalwareDomainList').get('result')))
    print("Reports from opera: %s" %(url_report_json.get('scans', {}).get('Opera').get('result')))
    print("Reports from Malc0de: Database %s" %(url_report_json.get('scans', {}).get('Malc0de Database').get('result')))
    print("Reports from BitDefender: %s" %(url_report_json.get('scans', {}).get('BitDefender').get('result')))
    print("Reports from G-Data: %s" %(url_report_json.get('scans', {}).get('G-Data').get('result')))
    print("Reports from Wepawet: %s" %(url_report_json.get('scans', {}).get('Wepawet').get('result')))

    if url_report_json.get('positives',{})>=1:#if malware detected, send a warning
        print("\n\nBEWARE! The site %s is fraudulent" %(u))
    print('-----------------------------------------------')



    #Scanninf URL from Phishtank database
    #app_key='a32e5760efce8befe97d6e7f804874909fbd9ddd49f25a8b9ae7ffc45329e7c6'
    print('\n-----------------------------------------------\n-Scanning URL from Phishtank, please wait...')
    print('-----------------------------------------------')
    print('Querying Phishtank database for the site %s, please wait...\n' %(u))
    payload = {'url': str(u), 'app_key': 'a32e5760efce8befe97d6e7f804874909fbd9ddd49f25a8b9ae7ffc45329e7c6', 'format': 'json'}
    r = requests.post("http://checkurl.phishtank.com/checkurl/", data=payload)
    reponse_url_phTank=json.loads(r.text)
    print("Status: %s" %(reponse_url_phTank.get('meta',{}).get('status')))
    print("Request ID: %s\n" %(reponse_url_phTank.get('meta',{}).get('requestid')))
    print("RESULTS:-\nIn Database: %s" %(reponse_url_phTank.get('results',{}).get('in_database')))
    print("Phish ID: %s " %(reponse_url_phTank.get('results',{}).get('phish_id')))
    print("Verified: %s " %(reponse_url_phTank.get('results',{}).get('verified')))
    print("Phish page details: %s " %(reponse_url_phTank.get('results',{}).get('phish_detail_page')))
    print('\n---------------------------------------------')


    #google safe browsing
    print('\n-----------------------------------------------\n-Scanning URL from google safe browsing, please wait...')
    print('-------------------------------------------------')
    
    url = "https://sb-ssl.google.com/safebrowsing/api/lookup"
    #apikey='ABQIAAAAOx_KI3N5ccMTyo50XVhIbhTMJe_xQHX6vBy53Cfb-BR7ixDX8Q'
    querystring = {"client":"api","apikey":"ABQIAAAAOx_KI3N5ccMTyo50XVhIbhTMJe_xQHX6vBy53Cfb-BR7ixDX8Q","appver":"1.0","pver":"3.0","url":_url_encoded}

    response = requests.request("GET", url, params=querystring)
    print('The given URL %s : '%(_url_encoded))
    print(response.text)#load into a readable format.
    print('-------------------------------------------------')



if __name__ == "__main__":
    main(sys.argv[1:])  
