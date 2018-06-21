#!/usr/bin/env python3
# -*- coding=utf-8 -*-
# @Time     : 6/21/18 3:15 PM
# @Author   : riverchu
# @Site     : 
# @File     : testscan.py
# @Software : PyCharm

import unittest

from .resolveIP import *


class TestScan(unittest.TestCase):
    """测试类

    """

    def test_dot2int(self):
        self.assertEqual(dot2int_ip([0, 0, 0, 0]), 0)
        self.assertEqual(dot2int_ip([255, 255, 255, 255]), 4294967295)
        self.assertEqual(dot2int_ip([1, 2, 3, 4]), 16909060)
        self.assertEqual(dot2int_ip([192, 168, 0, 1]), 3232235521)

    def test_int2dot(self):
        self.assertEqual(int2dot_ip(0), '0.0.0.0')
        self.assertEqual(int2dot_ip(4294967295), '255.255.255.255')
        self.assertEqual(int2dot_ip(16909060), '1.2.3.4')
        self.assertEqual(int2dot_ip(3232235521), '192.168.0.1')

    def test_maskcalc(self):
        self.assertEqual(mask_calc(0, 36), '0-255')
        self.assertEqual(mask_calc(1, 36), '0-127')
        self.assertEqual(mask_calc(2, 36), '0-63')
        self.assertEqual(mask_calc(3, 36), '32-63')
        self.assertEqual(mask_calc(4, 36), '32-47')
        self.assertEqual(mask_calc(5, 36), '32-39')
        self.assertEqual(mask_calc(6, 36), '36-39')
        self.assertEqual(mask_calc(7, 36), '36-37')
        self.assertEqual(mask_calc(8, 36), '36')

    def test_rangeip(self):
        self.assertEqual(resolve_range_ip('192.168.0.0'), (3232235520, 3232235520))
        self.assertEqual(resolve_range_ip('192.168.0.0-0'), (3232235520, 3232235520))
        self.assertEqual(resolve_range_ip('192.168.0.0-1'), (3232235520, 3232235521))
        self.assertEqual(resolve_range_ip('192.168.0.1-2'), (3232235521, 3232235522))
        self.assertEqual(resolve_range_ip('192.168.0.1-255'), (3232235521, 3232235775))

    def test_rangeipl(self):
        self.assertEqual(resolve_range_ipl('192.168.0.0-192.168.0.0'), (3232235520, 3232235520))
        self.assertEqual(resolve_range_ipl('192.168.0.0-192.168.0.1'), (3232235520, 3232235521))
        self.assertEqual(resolve_range_ipl('192.168.0.1-192.168.0.2'), (3232235521, 3232235522))
        self.assertEqual(resolve_range_ipl('192.168.0.1-192.168.0.255'), (3232235521, 3232235775))
        self.assertEqual(resolve_range_ipl('0.0.0.0-255.255.255.255'), (0, 4294967295))

    def test_cidr(self):
        self.assertEqual(resolve_cidr('192.168.0.1/0'), (0, 4294967295))
        self.assertEqual(resolve_cidr('192.168.0.1/8'), (3221225472, 3238002687))
        self.assertEqual(resolve_cidr('192.168.0.1/16'), (3232235520, 3232301055))
        self.assertEqual(resolve_cidr('192.168.0.1/22'), (3232235520, 3232236543))
        self.assertEqual(resolve_cidr('192.168.0.1/24'), (3232235520, 3232235775))
        self.assertEqual(resolve_cidr('192.168.0.1/30'), (3232235520, 3232235523))

    def test_isIP(self):
        self.assertEqual(is_ip('test'), 0)
        self.assertEqual(is_ip('@#!0'), 0)
        self.assertEqual(is_ip('....'), 0)
        self.assertEqual(is_ip('a.b.c.d'), 0)
        self.assertEqual(is_ip('1.2.3.4.'), 0)
        self.assertEqual(is_ip('192.168.0.-1'), 0)
        self.assertEqual(is_ip('192.168.0.1/0'), 1)
        self.assertEqual(is_ip('192.168.0.0-0'), 2)
        self.assertEqual(is_ip('192.168.0.0'), 2)
        self.assertEqual(is_ip('192.168.0.0-192.168.0.0'), 3)

    def test_resolvehost(self):
        pass

    def test_resolveip(self):
        self.assertEqual(list(resolve_ip('192.168.0.0')), ['192.168.0.0'])
        self.assertEqual(list(resolve_ip('192.168.0.0/30')),
                         ['192.168.0.0', '192.168.0.1', '192.168.0.2', '192.168.0.3', ])
        self.assertEqual(list(resolve_ip('192.168.0.0-1')), ['192.168.0.0', '192.168.0.1'])
        self.assertEqual(list(resolve_ip('192.168.0.0-192.168.0.1')), ['192.168.0.0', '192.168.0.1'])
