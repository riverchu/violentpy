#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

import pexpect

LOGIN =['Last login']
SHELL = 'bash'
PROMPT=['# ','>>> ','> ','\$ ','$ ']

def send_command(child,cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    response = str(child.before,encoding="utf-8")[len(cmd)+2:]
    print(response,end='')
    return input()

def trans_passwd(child,passwd):
    try:
        child.sendline(passwd)
        child.expect(LOGIN)
        child.sendline(SHELL)
        child.expect(PROMPT)
        return child
    except Exception as e:
        print('[-]',e)
        return None

def login_ssh(child,user,passwd):
    ssh_newkey='Are you sure you want to continue connecting'
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey,'[P|p]assword:'])
    if ret==0:
        print("[-] Error Connecting")
        return
    elif ret==1:
        child.sendline('yes')
        ret = child.expect([pexpect.TIMEOUT,'[P|p]assword'])
        if ret==0:
            print("[-] Error Connecting")
            return
        else:
            return trans_passwd(child,passwd)
    elif ret==2:
        return trans_passwd(child,passwd)

def connect(user,host,passwd):
    sshConn='ssh '+user+'@'+host
    try:
        child = pexpect.spawn(sshConn)
        #fout = open('mylog.txt','wb')
        #child.logfile = fout
        login_ssh(child,user,passwd)
        return child
    except Exception as e:
        print('[-]',e)

def start_ssh():
    host = '10.108.36.71'
    user = 'root'
    passwd = 'indigosrpi'
    child = connect(user,host,passwd)

    response = send_command(child,'cat /etc/shadow|grep root')
    while response and response!="exit":
        response = send_command(child,response)

if __name__=="__main__":
    start_ssh()
