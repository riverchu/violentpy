#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

import nmap

def nmap_scan(tgtHost,tgtPort):
    nmScan = nmap.PortScanner()
    result = nmScan.scan(tgtHost,str(tgtPort))
    if result['scan'].__contains__(tgtHost):
        return nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
    else:
        return None


