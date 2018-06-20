#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import pexpect
from pexpect import pxssh

import optparse

LOGIN = 'Last login'
SHELL = 'bash'
PROMPT = ['# ', '>>> ', '> ', '\$ ', '$ ']
TIMEOUT = 5


def close_connection(s):
    """关闭连接"""
    s.close()


def send_command_pexpect(child, cmd):
    """pexpect 通过ssh发送命令，返回信息"""
    child.sendline(cmd)
    child.expect(PROMPT)
    return str(child.before, encoding="utf-8")[len(cmd) + 2:]


def trans_passwd_pexpect(child, passwd):
    """pexpect 测试ssh密码 """
    try:
        child.sendline(passwd)
        ret = child.expect([pexpect.TIMEOUT, LOGIN, '[P|p]assword'])
        if ret == 0:
            print('[-] Time out.')
            return None
        elif ret == 1:
            child.sendline(SHELL)
            child.expect(PROMPT)
            return child
        elif ret == 2:
            print('[-] Wrong password.')
            return None
        else:
            print('[-] Unknown error.')
            return None
    except Exception as e:
        print('[-]', e)
        return None


def login_ssh_pexpect(child, passwd):
    """pexpect建立与目标主机连接，尝试登录"""
    ssh_newkey = 'Are you sure you want to continue connecting'
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword:'])
    if ret == 0:
        print("[-] Error Connecting")
        return None
    elif ret == 1:
        child.sendline('yes')
        ret = child.expect([pexpect.TIMEOUT, '[P|p]assword'])
        if ret == 0:
            print("[-] Error Connecting")
            return None
        else:
            return trans_passwd_pexpect(child, passwd)
    elif ret == 2:
        return trans_passwd_pexpect(child, passwd)


def com_ssh_pexpect(child, command='whoami && pwd'):
    """pexpect ssh发送命令"""
    try:
        while command != "exit":
            response = send_command_pexpect(child, command)
            print(response, end='')
            command = input()
    except KeyboardInterrupt as e:
        print('\n[-] Error: KeyboardInterrupt', e)
    except Exception as e:
        print('[-] Error:', e)
    finally:
        close_connection(child)


def connect_pexpect(host, user, passwd):
    """pexpect 连接

    :param host: 目标主机
    :param user: 目标用户
    :param passwd: 登录密码
    :return: 登录句柄 登录失败返回None
    """
    ssh_connect = 'ssh ' + user + '@' + host
    try:
        child = pexpect.spawn(ssh_connect, timeout=TIMEOUT)
        # fout = open('mylog.txt', 'wb')
        # child.logfile = fout
        return login_ssh_pexpect(child, passwd)
    except Exception as e:
        print('[-] Error:', e)


def send_command(s, cmd):
    """pxssh 发送命令，返回信息"""
    s.sendline(cmd)
    s.prompt()
    ret = s.before.split('\n', 1)[1].strip().strip('\r')
    # ret = str(s.before, encoding="utf-8").split('\n', 1)[1].strip()#[len(cmd):]
    return ret


def com_ssh_realtime(s, command='cat /etc/shadow|grep root'):
    """pxssh ssh发送命令，实时回应"""
    try:
        while command != "exit":
            response = send_command(s, command)
            print(response, end='')
            command = input()
    except KeyboardInterrupt as e:
        print('\n[-] Error: KeyboardInterrupt', e)
    except Exception as e:
        print('[-] Error:', e)
    finally:
        s.logout()
        close_connection(s)


def connect(host, user, passwd):
    """pxssh连接ssh

    :param host:目标主机
    :param user:目标用户
    :param passwd:密码
    :return: 连接句柄 登录失败返回None
    """
    try:
        s = pxssh.pxssh(encoding='utf-8')
        s.login(host, user, passwd)
        return s
    except Exception as e:
        print('[-] Error:', e)
        return None


def start_ssh(host, user, passwd):
    """ssh连接入口函数 选择合适方式登录及登录后操作

    :param host:目标主机
    :param user:目标用户
    :param passwd:密码
    :return:登录句柄 登录失败返回None
    """
    try:
        s = connect(host, user, passwd)
        if not s:
            print('[-] Connect Failed.')
            return None
        # com_ssh_realtime(child)
        return s
    except Exception as e:
        print('[-] Error:', e)


def ret_login_handle(login_info):
    """处理字典格式登录信息 返回登录句柄

    :param login_info: 登录信息字典格式{'host': '1.2.3.4', 'user': 'root', 'type': 'password', 'key': None}
    :return: 登录句柄
    """
    if login_info['type'] == 'password' and login_info['key'] is not None:
        handle = start_ssh(login_info['ip'], login_info['user'], login_info['key'])
        return handle


def main():
    """单独调用时的入口函数"""
    parser = optparse.OptionParser('usage %prog ' + '-H <target host> -u <user> -p <password list>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-u', dest='user', type='string', help='specify the user')
    parser.add_option('-p', dest='passwd', type='string', help='specify password')
    (options, args) = parser.parse_args()
    host = options.tgtHost
    user = options.user
    passwd = options.passwd

    if host is None or passwd is None or user is None:
        print(parser.usage)
        exit(0)

    start_ssh(host, user, passwd)


if __name__ == "__main__":
    main()
