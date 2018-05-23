#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

from socket import *

def dot2intIP(ip):
	ip = (int(ip[0])<<24) + (int(ip[1])<<16) + (int(ip[2])<<8) + int(ip[3])
	return ip

def int2dotIP(intIP):
	ip=[0,0,0,0]
	ip[0]=intIP>>24;
	ip[1]=(intIP>>16) & 255
	ip[2]=(intIP>>8) & 255
	ip[3]=(intIP) & 255
	return str(ip[0])+'.'+str(ip[1])+'.'+str(ip[2])+'.'+str(ip[3])

def maskCalc(mask,ipl):
	i = 0
	for c in range(mask):
		i = (i<<1)+1
	i = i<<(8-mask)

	i = i&int(ipl)

	return str(i)+'-'+str(i+2**(8-mask))

#192.168.1.1-255
def resolveRangeIP(ipL):
	maxip = [0,0,0,0]
	minip = [0,0,0,0]

	ip = ipL.split('.')

	for x in range(4):
		if ip[x].find('-')!=-1:
			s,e = ip[x].split('-')
			minip[x] = int(s)
			maxip[x] = int(e)
		else:
			maxip[x] = int(ip[x])
			minip[x] = int(ip[x])

	return dot2intIP(minip),dot2intIP(maxip)

#192.168.1.1-192.168.1.255
def resolveRangeIPL(ipL):
	minip,maxip = ipL.split('-')
	minip = minip.split('.')
	maxip = maxip.split('.')
	return dot2intIP(minip),dot2intIP(maxip)

#192.168.1.1/24
def resolveCIDR(ipL):
	ip,mask=ipL.split('/')

	ip=ip.split('.')
	mask = int(mask)

	if mask<=8:
		ranip = maskCalc(mask,ip[0])
		return resolveRangeIP(ranip+'.0-255.0-255.0-255')
	elif mask<=16:
		ranip = maskCalc(mask-8,ip[1])
		return resolveRangeIP(ip[0]+'.'+ranip+'.0-255.0-255')
	elif mask<=24:
		ranip = maskCalc(mask-16,ip[2])
		return resolveRangeIP(ip[0]+'.'+ip[1]+'.'+ranip+'.0-255')
	elif mask<=30:
		ranip = maskCalc(mask-24,ip[3])
		return resolveRangeIP(ip[0]+'.'+ip[1]+'.'+ip[2]+'.'+ranip)
	else:
		print('[-]Input wrong ip range.')
		exit(0)

def isIP(string):
    try:
        if string.find('/')!=-1:
            ip,mask = string.split('/')
            if int(mask)<0 or int(mask)>32:return 0
            ip=ip.split('.')
            if len(ip)!=4:return 0
            for i in ip:
                if int(i)<0 or int(i)>255:return 0
            return 1
        ip = string.split('.')
        if len(ip)==4:
            for i in ip:
                if i.find('-')!=-1:
                    s,e=i.split('-')
                    if int(s)<0 or int(s)>255:return 0
                    if int(e)<0 or int(e)>255:return 0
                    if int(s)>int(e):return 0
                elif int(i)<0 or int(i)>255:return 0
            return 2
        elif len(ip)==7:
            for i in ip[:3]+ip[4:]:
                if int(i)<0 or int(i)>255:return 0
            s,e=ip[3].split('-')
            if int(s)<0 or int(s)>255:return 0
            if int(e)<0 or int(e)>255:return 0
            return 3
        else:
            return 0
    except:
        return 0

def resolve_host(tgtHost):
    try:
        tgtIP = gethostbyname(tgtHost)
    except Exception as e:
        return False
    try:
        tgtName = gethostbyaddr(tgtIP)
        return tgtName[0]
    except:
        return tgtIP

def resolveIP(iprange):
    ipType = isIP(iprange)
    if ipType==1:
        start,end = resolveCIDR(iprange)
    elif ipType==2:
        start,end = resolveRangeIP(iprange)
    elif ipType==3:
        start,end = resolveRangeIPL(iprange)
    else:
        print('[-]Input wrong ip range.')
        exit(0)

    for ip in range(start,end+1):
        yield int2dotIP(ip)

if __name__ == "__main__":
    print("[+] example:192.168.1.1/28")
    print(list(resolveIP("192.168.1.1/28")))

#Question
#dui yu CIDR model ,resolve to broadcast and subnet name
