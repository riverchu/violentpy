#!/usr/bin/env python3
# coding:utf-8

import crypt

DICTIONARY = '/root/h/data/dictionary/common/top100thousand.txt'


def brute_unix_passwd(method, salt, passwd_hash, *, dic=DICTIONARY, name=None):
    """单条unix密码信息爆破

    :param method:hash方式
    :param salt:salt值
    :param passwd_hash:密码hash值
    :param dic:密码字典路径
    :param name:
    :return: 破解结果 password明文信息
    """
    try:
        hashinfo = '$' + method + '$'
        hashinfo += salt if salt else ''

        if name is not None:
            crypted_word = crypt.crypt(name, hashinfo)
            if crypted_word == hashinfo + '$' + passwd_hash:
                return name

        with open(dic, 'r') as dicFile:
            for word in dicFile:
                word = word.strip('\n').strip('\r')
                crypted_word = crypt.crypt(word, hashinfo)
                if crypted_word == hashinfo + '$' + passwd_hash:
                    return word
        return None
    except Exception as e:
        print('[-] brute_unix_passwd :', e)


def test_passwd(line, passwd):
    """测试passwd是否为相应密码

    :param line:
    :param passwd:
    :return:
    """
    try:
        format_hash_info = format_hashinfo(line)
        if format_hash_info:
            hashinfo = '$' + format_hash_info[1] + '$'
            hashinfo += format_hash_info[2] if format_hash_info[2] else ''

            crypted_word = crypt.crypt(passwd, hashinfo)
            if crypted_word == hashinfo + '$' + format_hash_info[3]:
                return True
            else:
                return False
    except Exception as e:
        print('[-] crack_unix_passwd :', e)


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
            ret = brute_unix_passwd(*format_hash_info[1:], dic=dic, name=format_hash_info[0])
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


def crack_bot_unix_passwd(ip, passwd_file_info, dic):
    """破解bot主机密码文件

    :param ip: 主机ip
    :param passwd_file_info: 密码文件内容
    :param dic: 密钥字典
    :param file: 存储文件目录
    :return:
    """
    if passwd_file_info is None or passwd_file_info == '':
        return None

    # 记录密码文件
    pass_bruteinfo = dict()
    pass_bruteinfo['ip'] = ip
    pass_bruteinfo['account'] = {}
    if passwd_file_info:
        # 破解密码文件内密码
        for line in passwd_file_info.split('\r\n'):
            if len(line) < 4:
                continue
            passwd_info = crack_unix_passwd(line, dic=dic)
            if passwd_info['user'] != 'BannedUser':
                pass_bruteinfo['account'][passwd_info['user']] = {}
                pass_bruteinfo['account'][passwd_info['user']]['password'] = passwd_info['password']
                pass_bruteinfo['account'][passwd_info['user']]['hash'] = line

    return pass_bruteinfo


def update_passwd_json(info, dic):
    """update password file

    :param info:
    :param dic:
    :return:
    """
    for host in info:
        print('[*] updating ' + host)
        host_info = info[host]
        account_info = host_info['account']
        for user in account_info:
            user_info = account_info[user]
            if user_info['password'] is None:
                passwd_info = crack_unix_passwd(user_info['hash'], dic)
                user_info['password'] = passwd_info['password']
            elif test_passwd(user_info['hash'], user_info['password']) is False:
                passwd_info = crack_unix_passwd(user_info['hash'], dic)
                user_info['password'] = passwd_info['password']

    return info


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
