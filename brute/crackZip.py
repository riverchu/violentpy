#!/usr/bin/env python3
# coding=utf-8
__author__ = "riverchu"

import zipfile
import optparse
from threading import *

DIC_PATH = '../data/'
EXTRACT_PATH = './extract_here'

PASSWD = ''

MAX_THREAD = 10
THREADPOOL = BoundedSemaphore(value=MAX_THREAD)


def extract_file(zfile, passwd):
    global PASSWD
    try:
        zfile.extractall(path=EXTRACT_PATH, pwd=passwd)
        PASSWD = passwd
    except Exception as e:
        print('[-] Error:', e)
    finally:
        THREADPOOL.release()


def crack_zip(file_path='evil.zip', dic_name="dictionary.txt"):
    parser = optparse.OptionParser("usage%prog " + "-f <zipfile> -d <dictionary>")
    parser.add_option('-f', dest='zipFileName', type='string', help='specify zip file')
    parser.add_option('-d', dest='dictionaryName', type='string', help='specify dictionary file')
    (options, args) = parser.parse_args()
    if options.zipFileName is not None:
        file_path = options.zipFileName
    if options.dictionaryName is not None:
        dic_name = options.dictionaryName

    print("[+] Cracking " + file_path + " with dictionary " + dic_name)

    global PASSWD
    zfile = zipfile.ZipFile(file_path)
    pass_file = open(DIC_PATH + dic_name)
    threads = []

    for line in pass_file.readlines():
        THREADPOOL.acquire()
        passwd = bytes(line.strip('\n'), encoding="utf8")
        t = Thread(target=extract_file, args=(zfile, passwd))
        threads.append(t)
        t.setDaemon(True)
        t.start()

    for t in threads:
        if PASSWD is True:
            break
        t.join()

    PASSWD = str(PASSWD, encoding="utf8")
    print("[+] Found " + file_path + "'s password : " + PASSWD)


if __name__ == "__main__":
    crack_zip()
