#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

import pexpect
from pexpect import pxssh
import optparse

LOGIN ='Last login'
SHELL ='bash'
PROMPT=['# ','>>> ','> ','\$ ','$ ']
TIMEOUT=5

def send_command_pexpect(child,cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    return str(child.before,encoding="utf-8")[len(cmd)+2:]

def send_command(s,cmd):
    s.sendline(cmd)
    s.prompt()
    ret = str(s.before,encoding="utf-8").split('\n',1)[1]#[len(cmd):]
    return ret

def trans_passwd_pexpect(child,passwd):
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

def login_ssh_pexpect(child,user,passwd):
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
            return trans_passwd_pexpect(child,passwd)
    elif ret==2:
        return trans_passwd_pexpect(child,passwd)

def com_ssh_pexpect(child,command='whoami && pwd'):
    try:
        while command!="exit":
            response = send_command_pexpect(child,command)
            print(response,end='')
            command = input()
    except KeyboardInterrupt as e:
        print('\n[-] Error: KeyboardInterrupt')
    except Exception as e:
        print('[-] Error:',e)
    finally:
        child.close()

def com_ssh(s,command='whoami && pwd'):
    try:
        while command!="exit":
            response = send_command(s,command)
            print(response,end='')
            command = input()
    except KeyboardInterrupt as e:
        print('\n[-] Error: KeyboardInterrupt')
    except Exception as e:
        print('[-] Error:',e)
    finally:
        s.logout()
        s.close()

def connect_pexpect(host,user,passwd):
    sshConn='ssh '+user+'@'+host
    try:
        child = pexpect.spawn(sshConn,timeout=TIMEOUT)
        #fout = open('mylog.txt','wb')
        #child.logfile = fout
        return login_ssh_pexpect(child,user,passwd)
    except Exception as e:
        print('[-] Error:',e)

def connect(host,user,passwd):
    try:
        s = pxssh.pxssh()
        s.login(host,user,passwd)
        return s
    except Exception as e:
        print('[-] Error:',e)

def start_ssh(host,user,passwd):
    try:
        child = connect(host,user,passwd)
        if not child:
            print('[-] Connect Failed.')
            return
        com_ssh(child)
    except Exception as e:
        print('[-] Error:',e)

def main():
    parser = optparse.OptionParser('usage %prog '+'-H <target host> -u <user> -p <password list>')
    parser.add_option('-H',dest = 'tgtHost',type='string',help='specify target host')
    parser.add_option('-u',dest = 'user',type='string',help='specify the user')
    parser.add_option('-p',dest = 'passwd',type='string',help='specify password')
    (options,args)=parser.parse_args()
    host = options.tgtHost
    user = options.user
    passwd = options.passwd

    if host==None or passwd==None or user==None:
        print(parser.usage)
        exit(0)

    start_ssh(host,user,passwd)

if __name__=="__main__":
    main()
