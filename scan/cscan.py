#!/usr/bin/env python3
#coding=utf-8
__author__="riverchu"

import os
import sys
import optparse
from socket import *
from threading import *

from nmapscan import *
from resolveIP import *

#SAY_HELLO = "Hello bro,I'm a hacker.\r\n"
SAY_HELLO = "Hello bro.\r\n"
SCREENLOCK = Semaphore(value=1)
MAX_THREAD = 10
THREADPOOL = BoundedSemaphore(value=MAX_THREAD)

def check_vulns(banner,filename):
    f = open(filename,'r')
    for line in f.readlines():
        if line.strip('\n') in banner:
            print("[+] Server is vulnerable: " + banner.strip('\n'))

def ret_banner(tgtHost,tgtPort):
    banner = None
    try:
        s = socket(AF_INET,SOCK_STREAM)
        s.connect((tgtHost,tgtPort))
        s.send(bytes(SAY_HELLO,encoding="utf8"))
        banner = s.recv(256).decode().strip()
        s.close()
        return banner
    except:
        #if banner:
        #    banner = str(banner,encoding="utf8").strip()
        return banner

def output_result(tgtHost,tgtPort,string,typeStr):
    SCREENLOCK.acquire()
    if typeStr == 'banner' and string:
        print("[+] "+tgtHost+" : %d/tcp open"% tgtPort)
        print("[+] Banners: "+string)
    elif typeStr == 'state' and string:
        print("[+] "+tgtHost+" tcp/"+str(tgtPort)+" "+string)
    else:
        pass
        #print("[-] "+tgtHost+" : %d/tcp closed"% tgtPort)
    SCREENLOCK.release()

def port_scan(tgtHost,tgtPorts):
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        tgtPort = int(tgtPort.strip())
        #print("[+] Scanning "+tgtHost+" port: "+str(tgtPort))
        banner = ret_banner(tgtHost,tgtPort)
        output_result(tgtHost,tgtPort,banner,'banner')
        #state = nmap_scan(tgtHost,tgtPort)
        #output_result(tgtHost,tgtPort,state,'state')
    THREADPOOL.release()

def host_scan(tgtHost,tgtPorts):
    if isIP(tgtHost):
        threads = []
        for tgtIP in resolveIP(tgtHost):
            print("[+] Scanning "+tgtIP)
            THREADPOOL.acquire()
            t = Thread(target=port_scan,args=(tgtIP,tgtPorts))
            threads.append(t)
            t.setDaemon(True)
            t.start()
            #port_scan(tgtIP,tgtPorts)
        for t in threads:
            t.join()
    else:
        res = resolve_host(tgtHost)
        if res:
            #print("[+] Scanning "+res)
            port_scan(tgtHost,tgtPorts)
        else:
            print("[-] Cannot resolve '%s': Unknown host"%tgtHost)

def cscan():
    parser = optparse.OptionParser('usage %prog '+'-H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
    if (tgtHost == None)|(tgtPorts[0] == None):
        print(parser.usage)
        exit(0)

    host_scan(tgtHost,tgtPorts)

if __name__ == "__main__":
    cscan()
