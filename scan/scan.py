#!/usr/bin/env python3
#coding=utf-8
__author__="riverchu"

import socket
import os
import sys

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

def resolvRangeIP(ipL):
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

def resolvRangeIPL(ipL):
	minip,maxip = ipL.split('-')
	minip = minip.split('.')
	maxip = maxip.split('.')
	return dot2intIP(minip),dot2intIP(maxip)

def resolvCIDR(ipL):
	ip,mask=ipL.split('/')

	ip=ip.split('.')
	mask = int(mask)

	if mask<=8:
		ranip = maskCalc(mask,ip[0])
		return resolvRangeIP(ranip+'.0-255.0-255.0-255')
	elif mask<=16:
		ranip = maskCalc(mask-8,ip[1])
		return resolvRangeIP(ip[0]+'.'+ranip+'.0-255.0-255')
	elif mask<=24:
		ranip = maskCalc(mask-16,ip[2])
		return resolvRangeIP(ip[0]+'.'+ip[1]+'.'+ranip+'.0-255')
	elif mask<=30:
		ranip = maskCalc(mask-24,ip[3])
		return resolvRangeIP(ip[0]+'.'+ip[1]+'.'+ip[2]+'.'+ranip)
	else:
		print('[-]Input wrong ip range.')
		exit(0)

def resolvIP(iprange):
	if iprange.find('-') != -1 and (iprange.find('-') != iprange.rfind('-') or iprange.rfind('.')-iprange.find('-')<4):
		start,end = resolvRangeIP(iprange)
	elif iprange.find('-') !=-1 and iprange.find('-') == iprange.rfind('-'):
		start,end = resolvRangeIPL(iprange)
	elif iprange.find('/') != -1:
		start,end = resolvCIDR(iprange)
	else:
		print('[-]Input wrong ip range.')
		exit(0)

	for ip in range(start,end+1):
		yield int2dotIP(ip)

def retBanner(ip,port):
	socket.setdefaulttimeout(0.2)
	s = socket.socket()
	try:
		s.connect((ip,port))
		banner = s.recv(1024)
		return str(banner)
	except:
		return "No banner--time out"

def checkVulns(banner,filename):
	f = open(filename,'r')
	for line in f.readlines():
		if line.strip('\n') in  banner:
			print("[+]Server is vulnerable: " + banner.strip('\n'))

def scan():
	if len(sys.argv) == 2:
		filename = sys.argv[1]
		if not os.path.isfile(filename):
			print('[-]'+filename+' does not exist.')
			exit(0)
		if not os.access(filename,os.R_OK):
			print('[-]'+filename+' access denied.')
			exit(0)
	else:
		print('[-]Usage: '+str(sys.argv[0])+' <vuln filename>.')
		exit(0)

	portList=[21,22,25,80,110,443]
	for ip in resolvIP('10.108.39.200/22'):
		for port in portList:
			banner = retBanner(ip,port)
			if banner !='No banner--time out':
				print('[+] '+str(ip)+': '+str(port)+'\tBanners:'+banner)
				checkVulns(banner,filename)

if __name__ == "__main__":
	scan()
