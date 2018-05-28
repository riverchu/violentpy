#!/usr/bin/env python3
# coding:utf-8

import crypt

def blastUnixPasswd(user,method,salt,passwd,*,dic='../data/dictionary.txt'):
    hashinfo = '$' + method + '$'
    hashinfo += salt+'$' if salt else ''
    hashinfo += passwd

    with open(dic,'r') as dicFile:
        for word in dicFile:
            word = word.strip('\n')
            cryptWord = crypt.crypt(word,hashinfo)
            if cryptWord == hashinfo:
                return word
        return

def format_hashinfo(line):
    if ':' in line:
        info = line.split(':')
        user = info[0].strip()
        hashinfo = info[1].strip()
        if hashinfo in ['*','!','!!','']: return

    hashinfo = hashinfo.split('$')
    if len(hashinfo) > 2:
        method = hashinfo[1]
        salt =hashinfo[2]
        passwd = hashinfo[3]
    else:
        method = hashinfo[1]
        salt = None
        passwd = hashinfo[2]

    return user,method,salt,passwd

def crack_unix_passwd(line,dic):
    formatHashInfo = format_hashinfo(line)
    ret = blastUnixPasswd(*formatHashInfo,dic=dic)
    if ret :
        return formatHashInfo[0],ret

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
        res = blastUnixPasswd(user,method,salt,passwd)
        if res:
            print('[+]Found %s\'s password: %s'%(user,res))
        else:
            print('[-]Password not found. ')

if __name__ == "__main__":
    crack()
