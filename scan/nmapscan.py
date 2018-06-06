#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import nmap
from .resolveIP import resolve_ip


def ret_info(dic, attr):
    if dic.__contains__(attr):
        return dic[attr]
    else:
        return None


def host_scan(tgt_host, tgt_port):
    nm_scan = nmap.PortScanner()
    result = nm_scan.scan(tgt_host, str(tgt_port))
    try:
        for ip in result['scan']:
            ip_info = ret_info(result['scan'], ip)
            # address = ret_info(ip_info, 'addresses')
            # mac = ret_info(address, 'mac')
            # vendor = ret_info(ip_info['vendor'], mac)
            port_info = ip_info['tcp'][int(tgt_port)]
            state = port_info['state']
            name = port_info['name']
            # return(ip,mac,vendor,int(tgtPort),name,state)
            return {'ip': ip, 'port': int(tgt_port), 'name': name, 'state': state}
    except Exception as e:
        print(e)


# 结构需更新
def nmap_scan(tgt_host, tgt_port):
    nm_scan = nmap.PortScanner()
    # print(tgt_host, tgt_port)
    result = nm_scan.scan(tgt_host, str(tgt_port))
    # print(result)
    try:
        for ip in result['scan']:
            ip_info = ret_info(result['scan'], ip)
            # address = ret_info(ip_info, 'addresses')
            # mac = ret_info(address, 'mac')
            # vendor = ret_info(ip_info['vendor'], mac)
            port_info = ip_info['tcp'][int(tgt_port)]
            state = port_info['state']
            name = port_info['name']
            # yield(ip,mac,vendor,int(tgtPort),name,state)
            # print({'ip': ip, 'port': int(tgt_port), 'name': name, 'state': state})
            yield {'ip': ip, 'port': int(tgt_port), 'name': name, 'state': state}
    except Exception as e:
        print('[-] Scan Error:', e)


def ssh_scan_onebyone(tgt_host, tgt_port):
    tgt_host = str(tgt_host)
    tgt_port = str(tgt_port)
    for host in resolve_ip(tgt_host):
        ret = host_scan(host, tgt_port)
        if host is None or host['state'] != 'open' or host['name'] != 'ssh':
            continue
        yield ret


# host range, str port
def ssh_scan_all(tgt_host, tgt_port):
    tgt_host = str(tgt_host)
    tgt_port = str(tgt_port)
    for host in nmap_scan(tgt_host, tgt_port):
        if host is None or host['state'] != 'open' or host['name'] != 'ssh':
            continue
        yield host


if __name__ == '__main__':
    for ret in nmap_scan('10.108.36.71/24', '22'):
        print(ret)
