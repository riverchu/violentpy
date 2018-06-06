#!/usr/bin/env python3
# coding:utf-8

import crypt

DICTIONARY = '/root/h/data/dictionary/common/top100thousand.txt'


def brute_unix_passwd(method, salt, passwd, *, dic=DICTIONARY):
    try:
        hashinfo = '$' + method + '$'
        hashinfo += salt+'$' if salt else ''
        hashinfo += passwd

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
            passwd = hashinfo[3]
        elif len(hashinfo) == 3:
            method = hashinfo[1]
            salt = None
            passwd = hashinfo[2]
        else:
            return

        return user, method, salt, passwd
    except Exception as e:
        print('[-] format_hashinfo :', e)


def crack_unix_passwd(line, dic):
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
    if not file_path:
        file_path = '/etc/shadow'

    with open(file_path, 'r') as passFile:
        for line in passFile.readlines():
            format_hash_info = format_hashinfo(line)
            if not format_hash_info:
                continue
            yield format_hash_info


def crack():
    for user, method, salt, passwd in get_unix_passwd_file():
        # print(user, method, salt, passwd)
        print('[*]Cracking password for:', user)
        res = brute_unix_passwd(method, salt, passwd)
        if res:
            print('[+]Found %s\'s password: %s' % (user, res))
        else:
            print('[-]Password not found. ')


if __name__ == "__main__":
    crack()
