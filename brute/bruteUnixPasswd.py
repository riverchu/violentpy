#!/usr/bin/env python3
# coding:utf-8

import crypt

DICTIONARY = '/root/h/data/dictionary/common/top100thousand.txt'


def brute_unix_passwd(user,method,salt,passwd,*,dic=DICTIONARY):
    try:
        hashinfo = '$' + method + '$'
        hashinfo += salt+'$' if salt else ''
        hashinfo += passwd

        with open(dic,'r') as dicFile:
            for word in dicFile:
                word = word.strip('\n').strip('\r')
                cryptWord = crypt.crypt(word, hashinfo)
                if cryptWord == hashinfo:
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
        formatHashInfo = format_hashinfo(line)
        if formatHashInfo:
            ret = brute_unix_passwd(*formatHashInfo, dic=dic)
            return {'user': formatHashInfo[0], 'password': ret}
        else:
            return {'user': 'BannedUser', 'password': None}
    except Exception as e:
        print('[-] crack_unix_passwd :', e)


def getUnixPasswdFile(filePath=None):
    if not filePath:
        filePath = '/etc/shadow'

    with open(filePath,'r') as passFile:
        for line in passFile.readlines():
            formatHashInfo = format_hashinfo(line)
            if not formatHashInfo:
                continue
            yield formatHashInfo

def crack():
    for user,method,salt,passwd in getUnixPasswdFile():
        #print(user,method,salt,passwd)
        print('[*]Cracking password for:',user)
        res = brute_unix_passwd(user,method,salt,passwd)
        if res:
            print('[+]Found %s\'s password: %s'%(user,res))
        else:
            print('[-]Password not found. ')

if __name__ == "__main__":
    crack()
