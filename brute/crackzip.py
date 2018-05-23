#!/usr/bin/env python3
# coding=utf-8
__author__="riverchu"

import time
import zipfile
import optparse
from threading import Thread

DIC_PATH='../data/'
EXTRACT_PATH='./extract_here'

PASSWD = ''

def extract_file(zFile,passwd):
    global PASSWD
    try:
        zFile.extractall(path=EXTRACT_PATH,pwd=passwd)
        PASSWD = passwd
        return True
    except Exception as e:
        return None

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

    for line in passFile.readlines():
        passwd = bytes(line.strip('\n'),encoding="utf8")
        t = Thread(target=extract_file,args=(zFile,passwd))
        t.start()

    while not PASSWD:
        time.sleep(1)

    PASSWD = str(PASSWD,encoding="utf8")
    print("[+] Found "+filePath+"'s password : "+PASSWD)

if __name__ == "__main__":
    crack_zip()
