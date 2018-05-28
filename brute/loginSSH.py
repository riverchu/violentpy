#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

import pexpect

LOGIN ='Last login'
SHELL ='bash'
PROMPT=['# ','>>> ','> ','\$ ','$ ']
TIMEOUT=5

def send_command(child,cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    return str(child.before,encoding="utf-8")[len(cmd)+2:]

def trans_passwd(child,passwd):
    try:
        child.sendline(passwd)
        ret = child.expect([pexpect.TIMEOUT,LOGIN,'[P|p]assword'])
        if ret==0:
            print('[-] Time out.')
            return None
        elif ret==1:
            child.sendline(SHELL)
            child.expect(PROMPT)
            return child
        elif ret==2:
            print('[-] Wrong password.')
            return None
        else:
            print('[-] Unknown error.')
            return None
    except Exception as e:
        print('[-]',e)
        return None

def login_ssh(child,user,passwd):
    ssh_newkey='Are you sure you want to continue connecting'
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey,'[P|p]assword:'])
    if ret==0:
        print("[-] Error Connecting")
        return None
    elif ret==1:
        child.sendline('yes')
        ret = child.expect([pexpect.TIMEOUT,'[P|p]assword'])
        if ret==0:
            print("[-] Error Connecting")
            return None
        else:
            return trans_passwd(child,passwd)
    elif ret==2:
        return trans_passwd(child,passwd)

def connect(user,host,passwd):
    sshConn='ssh '+user+'@'+host
    try:
        child = pexpect.spawn(sshConn,timeout=TIMEOUT)
        #fout = open('mylog.txt','wb')
        #child.logfile = fout
        return login_ssh(child,user,passwd)
    except Exception as e:
        print('[-]',e)

def start_ssh():
    host = '10.108.36.71'
    user = 'root'
    passwd = 'indigosrpi'
    child = connect(user,host,passwd)

    if not child: exit(0)

    command = 'cat /etc/shadow|grep root'
    while command and command!="exit":
        response = send_command(child,command)
        print(response,end='')
        command = input()

if __name__=="__main__":
    start_ssh()
