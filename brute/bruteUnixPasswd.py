#!/usr/bin/env python3
# coding:utf-8

import crypt

DICTIONARY = '/root/h/data/dictionary/common/top100thousand.txt'


def brute_unix_passwd(method, salt, passwd_hash, *, dic=DICTIONARY):
    """单条unix密码信息爆破

    :param method:hash方式
    :param salt:salt值
    :param passwd_hash:密码hash值
    :param dic:密码字典路径
    :return: 破解结果 password明文信息
    """
    try:
        hashinfo = '$' + method + '$'
        hashinfo += salt + '$' if salt else ''
        hashinfo += passwd_hash

        with open(dic, 'r') as dicFile:
            for word in dicFile:
                word = word.strip('\n').strip('\r')
                crypted_word = crypt.crypt(word, hashinfo)
                if crypted_word == hashinfo:
                    return word
        return None
    except Exception as e:
        print('[-] brute_unix_passwd :', e)


def format_hashinfo(line):
    """格式化unix账户密码信息

    :param line:单条unix账户密码信息
    :return:tuple格式:(user, method, salt, passwd)
    """
    try:
        if line is None:
            return

        if ':' in line:
            info = line.split(':')
            user = info[0].strip().strip('\r')
            hashinfo = info[1].strip().strip('\r')
            if hashinfo in ['*', '!', '!!', ''] or '$' not in hashinfo:
                return
        else:
            return

        hashinfo = hashinfo.split('$')
        if len(hashinfo) == 4:
            method = hashinfo[1]
            salt = hashinfo[2]
            passwd_hash = hashinfo[3]
        elif len(hashinfo) == 3:
            method = hashinfo[1]
            salt = None
            passwd_hash = hashinfo[2]
        else:
            return

        return user, method, salt, passwd_hash
    except Exception as e:
        print('[-] format_hashinfo :', e)


def crack_unix_passwd(line, dic):
    """破解单条unix账户密码信息

    :param line:单条unix账户密码信息
    :param dic:密钥字典文件
    :return:破解结果 字典格式{'user': user, 'password': password}
    """
    try:
        format_hash_info = format_hashinfo(line)
        if format_hash_info:
            ret = brute_unix_passwd(*format_hash_info[1:], dic=dic)
            return {'user': format_hash_info[0], 'password': ret}
        else:
            return {'user': 'BannedUser', 'password': None}
    except Exception as e:
        print('[-] crack_unix_passwd :', e)


def get_unix_passwd_file(file_path=None):
    """自主获取unix密码

    :param file_path:密码文件路径
    :return: format_hash_info tuple格式:(user, method, salt, passwd)
    """
    if not file_path:
        file_path = '/etc/shadow'

    with open(file_path, 'r') as passFile:
        for line in passFile.readlines():
            format_hash_info = format_hashinfo(line)
            if not format_hash_info:
                continue
            yield format_hash_info


def crack():
    """爆破入口

    :return:
    """
    for user, method, salt, passwd_hash in get_unix_passwd_file():
        # print(user, method, salt, passwd)
        print('[*]Cracking password for:', user)
        res = brute_unix_passwd(method, salt, passwd_hash)
        if res:
            print('[+]Found %s\'s password: %s' % (user, res))
        else:
            print('[-]Password not found. ')


if __name__ == "__main__":
    crack()
