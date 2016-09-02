#!/usr/bin/python3

""" cisco_pwdecrypt.py: Simple tool to decrypt the 'enc_GroupPwd' variable in PCF files"""

__author__ = 'axcheron'
__license__ = 'Apache 2'
__version__ = '0.1'

import argparse
import random
from binascii import unhexlify
from passlib.hash import md5_crypt
from Crypto.Cipher import DES3
from hashlib import sha1
from re import search
from sys import exit


xlat = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 0x79,
        0x65, 0x77, 0x72, 0x6b, 0x6c,  0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42]


def pcf_parser(filename):

    try:
        hfile = open(filename, 'r')
    except Exception as e:
        print(e)
        exit(-1)

    keyword = "enc_GroupPwd="

    for line in hfile.readlines():
        if search(keyword, line, flags=0):
            enc = line.strip(keyword)
            pcf_decrypt(enc.rstrip())

    hfile.close()


def pcf_decrypt(hex_str):

    bin_str = bytearray(unhexlify(hex_str))
    ht = bin_str[0:20]
    enc = bytes(bin_str[40:])
    iv = bin_str

    ht[19] += 1
    hash = sha1()
    hash.update(bytes(ht))
    h2 = hash.digest()

    ht[19] += 2
    hash = sha1()
    hash.update(bytes(ht))
    h3 = hash.digest()

    key = h2 + h3[0:4]

    h3des = DES3.new(key, DES3.MODE_CBC, bytes(iv[0:8]))
    cleartext = h3des.decrypt(enc).decode('utf-8-sig')

    # TODO: Fix padding.
    quickfix = ""
    for c in cleartext:
        if ord(c) >= 31:
            quickfix += c

    print("[*] Result: %s" % quickfix)


def type7_decrypt(enc_pwd):

    index = int(enc_pwd[:2])
    enc_pwd = enc_pwd[2:].rstrip()
    pwd_hex = [enc_pwd[x:x + 2] for x in range(0, len(enc_pwd), 2)]
    cleartext = [chr(xlat[index+i] ^ int(pwd_hex[i], 16)) for i in range(0, len(pwd_hex))]

    print("[*] Result: %s" % ''.join(cleartext))


def _make_gen(reader):

    b = reader(1024 * 1024)
    while b:
        yield b
        b = reader(1024*1024)


def linecounter(filename):

    try:
        f = open(filename, 'rb')
    except IOError:
        print('[ERR] Cannot open:', filename)
        exit(-1)

    f_gen = _make_gen(f.raw.read)
    return sum( buf.count(b'\n') for buf in f_gen )


def type5_decrypt(enc_pwd, dict):

    print("[*] Bruteforcing 'type 5' hash...\n")

    # Count passwords in the wordlist
    passnum = linecounter(dict)
    print("\tFound %d passwords to test." % passnum)

    try:
        passf = open(dict, 'rb')
    except IOError:
        print('[ERR] Cannot open:', dict)
        exit(-1)

    # Splitting hash
    split_pwd = enc_pwd.split('$')

    print("\tTesting: %s" % enc_pwd)
    if split_pwd[1] == '1':
        print("\tHash Type = MD5")
    else:
        print("\t[ERR] Your 'type 5' hash is not valid.")
        exit(-1)

    print("\tSalt = %s" % split_pwd[2])
    print("\tHash = %s\n" % split_pwd[3])

    count = 0
    for line in passf.readlines():
        # random status
        if random.randint(1, 100) == 42:
            print("\t[Status] %d/%d password tested..." % (count, passnum))
        if md5_crypt.encrypt(line.rstrip(), salt=split_pwd[2]) == enc_pwd:
            print("\n[*] Password Found = %s" % line.decode("utf-8") )
            exit(0)
        count += 1
    print("\t[-] Password Not Found. You should try another dictionary.")


if __name__ == "__main__":
    '''This function parses and return arguments passed in'''
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description="Simple tool to decrypt Cisco passwords")

    # Add arguments
    parser.add_argument("-p", "--pcfvar", dest="pcfvar", action="store",
                        help="enc_GroupPwd Variable", type=str)

    parser.add_argument("-f", "--pcffile", dest="pcffile", action="store",
                        help=".pcf File", type=str)

    parser.add_argument("-t", "--type7", dest="type7", action="store",
                        help="Type 7 Password", type=str)

    parser.add_argument("-u", "--type5", dest="type5", action="store",
                        help="Type 5 Password", type=str)

    parser.add_argument("-d", "--dict", dest="dict", action="store",
                        help="Password list", type=str)

    args = parser.parse_args()

    if args.pcfvar:
        pcf_decrypt(args.pcfvar)
    elif args.pcffile:
        pcf_parser(args.pcffile)
    elif args.type7:
        type7_decrypt(args.type7)
    elif args.type5 and args.dict:
        type5_decrypt(args.type5, args.dict)
    elif args.type5 and args.dict is None:
        print("Type 5 requires -d or --dict.")
        exit(-1)
    else:
        parser.print_help()
        exit(-1)

