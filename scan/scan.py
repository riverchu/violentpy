#!/usr/bin/env python3
#coding=utf-8
__author__="riverchu"

import os
import sys
import optparse
from socket import *
from threading import *

from resolveIP import *

SAY_HELLO = "Hello bro,I'm a hacker.\r\n"
SCREENLOCK = Semaphore(value=1)

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
        banner = s.recv(256)
        s.close()
        return str(banner,encoding="utf8").strip()
    except:
        return banner

def port_scan(tgtHost,tgtPorts):
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        tgtPort = int(tgtPort.strip())
        #print("[+] Scanning "+tgtHost+" port: "+str(tgtPort))
        banner = ret_banner(tgtHost,tgtPort)
        SCREENLOCK.acquire()
        if banner:
            print("[+] "+tgtHost+" : %d/tcp open"% tgtPort)
            print("[+] Banners: "+banner)
        else:
            #print("[-] "+tgtHost+" : %d/tcp closed"% tgtPort)
            pass
        SCREENLOCK.release()

def host_scan(tgtHost,tgtPorts):
    if isIP(tgtHost):
        for tgtIP in resolveIP(tgtHost):
            #print("[+] Scanning "+tgtIP)
            t = Thread(target=port_scan,args=(tgtIP,tgtPorts))
            t.start()
            #port_scan(tgtIP,tgtPorts)
    else:
        res = resolve_host(tgtHost)
        if res:
            #print("[+] Scanning "+res)
            port_scan(tgtHost,tgtPorts)
        else:
            print("[-] Cannot resolve '%s': Unknown host"%tgtHost)

def scan():
    parser = optparse.OptionParser('usage %prog '+'-H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='int', help='specify target port')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
    if (tgtHost == None)|(tgtPorts[0] == None):
        print(parser.usage)
        exit(0)

    host_scan(tgtHost,tgtPorts)

if __name__ == "__main__":
    scan()
