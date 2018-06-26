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
PASS_DICTIONARY = DATA_PATH+'dictionary/common/top1million.txt'
BOT_PATH = DATA_PATH+'hData/bot/'
bot_info_file = 'bot_'+time.strftime('%Y-%m-%d_%Hh')+'.txt'
