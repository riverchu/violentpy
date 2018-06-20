#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

from socket import *


def dot2int_ip(ip):
    """点分法ip转为int形式ip

    :param ip:[1,2,3,4]
    :return:
    """
    ip = (int(ip[0]) << 24) + (int(ip[1]) << 16) + (int(ip[2]) << 8) + int(ip[3])
    return ip


def int2dot_ip(int_ip):
    """int形式ip转为点分法ip

    :param int_ip:ip的整数形式
    :return:
    """
    ip = [0, 0, 0, 0]
    ip[0] = int_ip >> 24
    ip[1] = (int_ip >> 16) & 255
    ip[2] = (int_ip >> 8) & 255
    ip[3] = int_ip & 255
    return str(ip[0]) + '.' + str(ip[1]) + '.' + str(ip[2]) + '.' + str(ip[3])


def mask_calc(mask, ipl):
    """计算掩码对对应ip范围

    :param mask:掩码长度
    :param ipl:ip点分的一位
    :return: 对应整数范围
    """
    if mask == 8:
        return str(ipl)
    i = 0
    for c in range(mask):
        i = (i << 1) + 1
    i = i << (8 - mask)

    i = i & int(ipl)

    suffix = 0
    for c in range(8-mask):
        suffix = (suffix << 1) + 1

    return str(i) + '-' + str(i + suffix)


def resolve_range_ip(ip):
    """解析范围型ip

    :param ipl: sample:192.168.1.1-255
    :return: (初始ip，结束ip)
    """
    maxip = [0, 0, 0, 0]
    minip = [0, 0, 0, 0]

    ip = ip.split('.')

    for x in range(4):
        if ip[x].find('-') != -1:
            s, e = ip[x].split('-')
            minip[x] = int(s)
            maxip[x] = int(e)
        else:
            maxip[x] = int(ip[x])
            minip[x] = int(ip[x])

    return dot2int_ip(minip), dot2int_ip(maxip)


def resolve_range_ipl(ipl):
    """解析对应范围ip

    :param ipl: 192.168.1.1-192.168.1.255
    :return: (初始ip，结束ip)
    """
    min_ip, max_ip = ipl.split('-')
    min_ip = min_ip.split('.')
    max_ip = max_ip.split('.')
    return dot2int_ip(min_ip), dot2int_ip(max_ip)


def resolve_cidr(ipl):
    """解析CIDR模式ip

    :param ipl: 192.168.1.1/24
    :return: (初始ip，结束ip)
    """
    ip, mask = ipl.split('/')

    ip = ip.split('.')
    mask = int(mask)

    if mask <= 8:
        ranip = mask_calc(mask, ip[0])
        return resolve_range_ip(ranip + '.0-255.0-255.0-255')
    elif mask <= 16:
        ranip = mask_calc(mask - 8, ip[1])
        return resolve_range_ip(ip[0] + '.' + ranip + '.0-255.0-255')
    elif mask <= 24:
        ranip = mask_calc(mask - 16, ip[2])
        return resolve_range_ip(ip[0] + '.' + ip[1] + '.' + ranip + '.0-255')
    elif mask <= 30:
        ranip = mask_calc(mask - 24, ip[3])
        return resolve_range_ip(ip[0] + '.' + ip[1] + '.' + ip[2] + '.' + ranip)
    else:
        print('[-]Input wrong ip range.')
        exit(0)


def is_ip(string):
    """判断是否为ip

    :param string:
    :return:
    """
    try:
        if string.find('/') != -1:
            ip, mask = string.split('/')
            if int(mask) < 0 or int(mask) > 32:
                return 0
            ip = ip.split('.')
            if len(ip) != 4:
                return 0
            for i in ip:
                if int(i) < 0 or int(i) > 255:
                    return 0
            return 1
        ip = string.split('.')
        if len(ip) == 4:
            for i in ip:
                if i.find('-') != -1:
                    s, e = i.split('-')
                    if int(s) < 0 or int(s) > 255:
                        return 0
                    if int(e) < 0 or int(e) > 255:
                        return 0
                    if int(s) > int(e):
                        return 0
                elif int(i) < 0 or int(i) > 255:
                    return 0
            return 2
        elif len(ip) == 7:
            for i in ip[:3] + ip[4:]:
                if int(i) < 0 or int(i) > 255:
                    return 0
            s, e = ip[3].split('-')
            if int(s) < 0 or int(s) > 255:
                return 0
            if int(e) < 0 or int(e) > 255:
                return 0
            return 3
        else:
            return 0
    except Exception as e:
        print('[-] Error', e)
        return 0


def resolve_host(tgt_host):
    """解析主机名

    :param tgt_host: 主机名 ip或域名
    :return:
    """
    try:
        tgt_ip = gethostbyname(tgt_host)
    except Exception as e:
        print('[-] Error', e)
        return False
    try:
        tgt_name = gethostbyaddr(tgt_ip)
        return tgt_name[0]
    except Exception as e:
        print('[-] Error', e)
        return tgt_ip


def resolve_ip(iprange):
    """解析ip

    :param iprange:
    :return: 迭代器返回ip
    """
    start, end = 0, 0
    ip_type = is_ip(iprange)
    if ip_type == 1:
        start, end = resolve_cidr(iprange)
    elif ip_type == 2:
        start, end = resolve_range_ip(iprange)
    elif ip_type == 3:
        start, end = resolve_range_ipl(iprange)
    else:
        print('[-]Input wrong ip range.')
        exit(0)

    for ip in range(start, end + 1):
        yield int2dot_ip(ip)


if __name__ == "__main__":
    print("[+] example:192.168.1.1/28")
    print(list(resolve_ip("10.108.36.71/23")))

# Question
# dui yu CIDR model ,resolve to broadcast and subnet name
