#!/usr/bin/env python3
# -*- coding=utf-8 -*-
# @Time     : 6/10/18 9:09 PM
# @Author   : riverchu
# @Site     : 
# @File     : global_var.py
# @Software : PyCharm

import time

MAX_CONNECTIONS = 10
OPERATE_INTERVAL = 3

DATA_PATH = '/root/h/data/'
SSH_DICTIONARY = DATA_PATH+'dictionary/common/online_brute.txt'
PASS_DICTIONARY = DATA_PATH+'dictionary/common/top100thousand.txt'
CHICKEN_PATH = DATA_PATH+'hData/chicken/'
chicken_info_file = 'chicken_'+time.strftime('%Y-%m-%d_%Hh')+'.txt'
