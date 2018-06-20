#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

# import os
# import sys
import optparse
# from socket import *
from threading import *

from .nmapscan import *
from .resolveIP import *

SAY_HELLO = "Hello bro.\r\n"
SCREENLOCK = Semaphore(value=1)
MAX_THREAD = 10
THREADPOOL = BoundedSemaphore(value=MAX_THREAD)


def check_vulns(banner, filename):
    """根据banner判断是否存在漏洞

    :param banner: banner内容
    :param filename: 存储带有漏洞的banner信息的文件
    :return:
    """
    f = open(filename, 'r')
    for line in f.readlines():
        if line.strip('\n') in banner:
            print("[+] Server is vulnerable: " + banner.strip('\n'))


def ret_banner(tgt_host, tgt_port):
    """返回banner

    :param tgt_host: 目标主机
    :param tgt_port: 目标端口
    :return: banner内容
    """
    banner = None
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((tgt_host, tgt_port))
        s.send(bytes(SAY_HELLO, encoding="utf8"))
        banner = s.recv(256).decode().strip()
        s.close()
        return banner
    except Exception as e:
        print('[-] Error:', e)
        # if banner:
        #    banner = str(banner,encoding="utf8").strip()
        return banner


def output_result(tgt_host, tgt_port, string, type_str):
    """输出扫描结果

    :param tgt_host:目标主机
    :param tgt_port:目标端口
    :param string:内容
    :param type_str:内容对应类型（banner或state）
    :return:
    """
    SCREENLOCK.acquire()
    if type_str == 'banner' and string:
        print("[+] " + tgt_host + " : %d/tcp open" % tgt_port)
        print("[+] Banners: " + string)
    elif type_str == 'state' and string:
        print("[+] " + tgt_host + " tcp/" + str(tgt_port) + " " + string)
    else:
        pass
        # print("[-] "+tgtHost+" : %d/tcp closed"% tgtPort)
    SCREENLOCK.release()


def port_scan(tgt_host, tgt_ports):
    """多端口扫描

    :param tgt_host: 目标主机
    :param tgt_ports: 目标端口
    :return:
    """
    setdefaulttimeout(1)
    for tgt_port in tgt_ports:
        tgt_port = int(tgt_port.strip())
        # print("[+] Scanning "+tgtHost+" port: "+str(tgtPort))
        banner = ret_banner(tgt_host, tgt_port)
        output_result(tgt_host, tgt_port, banner, 'banner')
        # state = nmap_scan(tgtHost,tgtPort)
        # output_result(tgtHost,tgtPort,state,'state')
    THREADPOOL.release()


def host_scan(tgt_host, tgt_ports):
    """多主机扫描

    :param tgt_host: 目标主机
    :param tgt_ports: 目标端口
    :return:
    """
    if is_ip(tgt_host):
        threads = []
        for tgtIP in resolve_ip(tgt_host):
            print("[+] Scanning " + tgtIP)
            THREADPOOL.acquire()
            t = Thread(target=port_scan, args=(tgtIP, tgt_ports))
            threads.append(t)
            t.setDaemon(True)
            t.start()
            # port_scan(tgtIP,tgtPorts)
        for t in threads:
            t.join()
    else:
        res = resolve_host(tgt_host)
        if res:
            # print("[+] Scanning "+res)
            port_scan(tgt_host, tgt_ports)
        else:
            print("[-] Cannot resolve '%s': Unknown host" % tgt_host)


def cscan():
    """diy扫描器入口

    :return:
    """
    parser = optparse.OptionParser('usage %prog ' + '-H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port')
    (options, args) = parser.parse_args()
    tgt_host = options.tgtHost
    tgt_ports = str(options.tgtPort).split(',')
    if tgt_host is None or tgt_ports[0] is None:
        print(parser.usage)
        exit(0)

    host_scan(tgt_host, tgt_ports)


if __name__ == "__main__":
    cscan()
