#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

import zipfile
import optparse
from threading import *

DIC_PATH='../data/'
EXTRACT_PATH='./extract_here'

PASSWD = ''

MAX_THREAD = 10
THREADPOOL = BoundedSemaphore(value=MAX_THREAD)

def extract_file(zFile,passwd):
    global PASSWD
    try:
        zFile.extractall(path=EXTRACT_PATH,pwd=passwd)
        PASSWD = passwd
    except Exception as e:
        pass
    finally:
        THREADPOOL.release()

def crack_zip(filePath='evil.zip',dicName="dictionary.txt"):
    parser = optparse.OptionParser("usage%prog "+"-f <zipfile> -d <dictionary>")
    parser.add_option('-f', dest='zipFileName', type='string', help='specify zip file')
    parser.add_option('-d', dest='dictionaryName', type='string', help='specify dictionary file')
    (options, args) = parser.parse_args()
    if options.zipFileName!=None:
        filePath = options.zipFileName
    if options.dictionaryName!=None:
        dicName = options.dictionaryName

    print("[+] Cracking "+filePath+" with dictionary "+dicName)

    global PASSWD
    zFile = zipfile.ZipFile(filePath)
    passFile = open(DIC_PATH+dicName)
    threads = []

    for line in passFile.readlines():
        THREADPOOL.acquire()
        passwd = bytes(line.strip('\n'),encoding="utf8")
        t = Thread(target=extract_file,args=(zFile,passwd))
        threads.append(t)
        t.setDaemon(True)
        t.start()

    for t in threads:
        if PASSWD: break
        t.join()

    PASSWD = str(PASSWD,encoding="utf8")
    print("[+] Found "+filePath+"'s password : "+PASSWD)

if __name__ == "__main__":
    crack_zip()
