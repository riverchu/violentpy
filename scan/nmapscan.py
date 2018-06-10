#!/usr/bin/env python3
# -*- coding=utf-8 -*-
__author__ = "riverchu"

import os
import nmap
import time
import socket
import random
import threading
from .resolveIP import resolve_ip, is_ip


class RiverNmapScan(object):
    """扫描器
    可直接调用的函数：
    :function scan_onebyone:
    :function scan_async:
    :function scan_all:
    :function reset:
    """
    timeout = 3

    def __init__(self):
        """
            初始化RiverNmapScan类
            scan_ret_list: [(host_1, scan_result_1),(host_2, scan_result_2),]
        """
        self.scan_ret_list = []
        self._server_port = random.randint(10000, 12000)
        self.nm = None
        self.recv_thread = None
        self.socket_server = None

    @staticmethod
    def ret_info(info, attr):
        """获取属性

        :param info: 扫描结果
        :param attr: 要获取的属性
        :return: 若存在属性则返回内容，若不存在则返回''
        """
        if isinstance(info, dict) is not True:
            return ''

        if info.__contains__(attr):
            return info[attr]
        else:
            return ''

    @staticmethod
    def format_ip_info(ip, ip_info, formated_info=None):
        """formate single ip info

        :param ip:
        :param ip_info:
        :param formated_info:
        :return:{ip, (mac, vendor), (tcp,{name, state, product, version}), (udp,{udp_info})}
        """
        ret_info = RiverNmapScan.ret_info

        if isinstance(formated_info, dict) is not True:
            formated_info = dict()

        formated_ip_info = dict()
        formated_info['ip'] = ip
        formated_info[ip] = formated_ip_info
        address = ret_info(ip_info, 'addresses')
        if address is not '':
            mac = ret_info(address, 'mac')
            formated_ip_info['mac'] = mac
            vendor = ret_info(ret_info(ip_info, 'vendor'), mac)
            formated_ip_info['vendor'] = vendor

        tcp_info = ret_info(ip_info, 'tcp')
        if tcp_info is not '':
            formated_ip_info['tcp'] = dict()
        udp_info = ret_info(ip_info, 'udp')
        if udp_info is not '':
            formated_ip_info['udp'] = udp_info

        for port in tcp_info:
            port_info = ret_info(tcp_info, port)
            formated_ip_info['tcp']['name'] = ret_info(port_info, 'name')
            formated_ip_info['tcp']['state'] = ret_info(port_info, 'state')
            formated_ip_info['tcp']['product'] = ret_info(port_info, 'product')
            formated_ip_info['tcp']['version'] = ret_info(port_info, 'version')
        return formated_info

    @staticmethod
    def format_info(info):
        """

        :param info: nmap return info
        :return: {timestamp, ip, (mac, vendor), (tcp,{name, state, product, version}), (udp,{udp_info})}
        """
        formated_info = dict()
        ret_info = RiverNmapScan.ret_info

        cmd_info = ret_info(info, 'nmap')
        scanstats = ret_info(cmd_info, 'scanstats')
        formated_info['timestamp'] = ret_info(scanstats, 'timestr')

        for ip in info['scan']:
            ip_info = ret_info(info['scan'], ip)
            formated_info = RiverNmapScan.format_ip_info(ip, ip_info, formated_info)

        return formated_info

    @staticmethod
    def filter_not_open(info, server_name=''):
        """filter info whose port is not open

        :param info:
        :param server_name:
        :return:
        """
        for ip in list(info.keys()):
            if is_ip(ip) != 0:
                break
        if RiverNmapScan.ret_info(info[ip], 'tcp') == '' \
                or RiverNmapScan.ret_info(info[ip]['tcp'], 'state') != 'open' \
                or (server_name != '' and RiverNmapScan.ret_info(info[ip]['tcp'], 'name') != server_name):
            return True
        return False

    def reset(self):
        """Reset扫描器状态

        :return:
        """
        self.scan_ret_list = []
        self._server_port = random.randint(10000, 12000)
        self.nm = None
        self.recv_thread = None
        self.socket_server = None

    def len_ret_list(self):
        """返回scan_ret_list长度

        :return:
        """
        return len(self.scan_ret_list)

    def add_ret_list(self, host, scan_ret):
        """将扫描结果添加进列表

        :param host: 扫描主机
        :param scan_ret: 扫描信息
        :return: None
        """
        if scan_ret['scan'] == {}:
            return

        client = socket.socket()
        client.connect(('localhost', self._server_port))
        send_msg = str(host) + '|||' + str(scan_ret)
        client.send(send_msg.encode())

    def pop_ret_list(self):
        """pop扫描列表scan_ret_list的第一项

        :return:scan_ret_list第一项
        """
        return self.scan_ret_list.pop(0)

    def recv_scan_info(self):
        """receive scan info by socket

        :return:
        """
        server = socket.socket()
        self.socket_server = server
        server.bind(('localhost', self._server_port))
        server.listen(5)

        while self.nm.still_scanning():
            try:
                conn, addr = server.accept()
                scan_info = conn.recv(1024).decode()
                host, scan_ret = scan_info.split('|||')
                host = host.strip('\'')
                scan_ret = eval(scan_ret)
                self.scan_ret_list.append((host, scan_ret))
            except Exception as e:
                if '[Errno 22]' not in str(e):
                    print('[-] Error:', e)
        server.close()

    def scan_ret_async(self, server_name=''):
        """

        :return: format scan info
        """
        while self.nm.still_scanning():
            self.nm.wait(2)
            while self.len_ret_list() > 0:
                info = self.format_info(self.pop_ret_list()[1])
                if self.filter_not_open(info, server_name) is True:
                    continue
                yield info

        time.sleep(self.timeout)
        if getattr(self.socket_server, '_closed') is False:
            self.socket_server.shutdown(2)
            self.socket_server.close()

        while self.len_ret_list() > 0:
            info = self.format_info(self.pop_ret_list()[1])
            if self.filter_not_open(info, server_name) is True:
                continue
            yield info

    def host_scan(self, tgt_host, tgt_port):
        """单个主机扫描

        :param tgt_host: 目标主机
        :param tgt_port: 目标端口
        :return: 返回字典{ip, port, name, state}
        """
        nm_scan = nmap.PortScanner()
        self.nm = nm_scan
        result = nm_scan.scan(tgt_host, str(tgt_port))
        try:
            for ip in result['scan']:
                ip_info = self.ret_info(result['scan'], ip)
                return RiverNmapScan.format_ip_info(ip, ip_info)
        except Exception as e:
            print(e)

    def start_scan_async(self, tgt_host, tgt_port):
        """scan async

        :param tgt_host: 目标主机
        :param tgt_port: 目标端口
        :return: None
        """
        nm_scan_async = nmap.PortScannerAsync()
        self.nm = nm_scan_async
        try:
            nm_scan_async.scan(tgt_host, tgt_port, callback=self.add_ret_list)
            t = threading.Thread(target=self.recv_scan_info, args=())
            t.start()
            self.recv_thread = t
        except Exception as e:
            print('[-] Error:', e)

    def scan(self, tgt_host, tgt_port):
        """普通扫描 阻塞

        :param tgt_host: 目标主机
        :param tgt_port: 目标端口
        :return: 迭代器返回字典{ip, port, name, state}
        """
        nm_scan = nmap.PortScanner()
        self.nm = nm_scan
        result = nm_scan.scan(tgt_host, str(tgt_port))
        try:
            for ip in result['scan']:
                ip_info = self.ret_info(result['scan'], ip)
                yield RiverNmapScan.format_ip_info(ip, ip_info)
        except Exception as e:
            print('[-] Scan Error:', e)

    def scan_onebyone(self, tgt_host, tgt_port, server_name=''):
        """按顺序扫描 迭代器方式返回信息

        :param tgt_host: 目标主机
        :param tgt_port: 目标端口
        :param server_name: 目标服务
        :return: 返回host_scan扫描结果
        """
        tgt_host = str(tgt_host)
        tgt_port = str(tgt_port)
        for host in resolve_ip(tgt_host):
            ret = self.host_scan(host, tgt_port)
            if ret is None or self.filter_not_open(ret, server_name) is True:
                continue
            yield ret

    def scan_async(self, tgt_host, tgt_port, server_name=''):
        """异步扫描 非阻塞
        扫描结果存入scan_ret_list

        :param tgt_host:目标主机
        :param tgt_port:目标端口
        :param server_name:目标服务
        :return: return ret_info_async
        """
        tgt_host = str(tgt_host)
        tgt_port = str(tgt_port)
        self.start_scan_async(tgt_host, tgt_port)

        return self.scan_ret_async(server_name)

    def scan_all(self, tgt_host, tgt_port, server_name=''):
        """全部扫描 阻塞进程

        :param tgt_host:目标主机
        :param tgt_port:目标端口
        :param server_name:目标服务
        :return: nmap_scan扫描结果
        """
        tgt_host = str(tgt_host)
        tgt_port = str(tgt_port)
        for ret in self.scan(tgt_host, tgt_port):
            if ret is None or self.filter_not_open(ret, server_name) is True:
                continue
            yield ret


# 测试
if __name__ == '__main__':
    test_scan = RiverNmapScan()
    start = time.time()
    for i in test_scan.scan_async('10.108.36.71/24', '22'):
        print(i)
    end = time.time()
    print('cost time:', end - start - test_scan.timeout)

    start = time.time()
    for i in test_scan.scan_all('10.108.36.71/24', '22'):
        print(i)
    end = time.time()
    print('cost time:', end - start)

    start = time.time()
    for i in test_scan.scan_onebyone('10.108.36.71/24', '22'):
        print(i)
    end = time.time()
    print('cost time:', end - start)
    print('end...')
