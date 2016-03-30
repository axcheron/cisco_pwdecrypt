#!/usr/bin/python3

""" cisco_pwdecrypt.py: Simple tool to decrypt the 'enc_GroupPwd' variable in PCF files"""

__author__ = 'axcheron'
__license__ = 'Apache 2'
__version__ = '0.1'

from optparse import OptionParser
from binascii import unhexlify
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

    print("Result: %s" % quickfix)


def type7_decrypt(enc_pwd):

    index = int(enc_pwd[:2])
    enc_pwd = enc_pwd[2:].rstrip()
    pwd_hex = [enc_pwd[x:x + 2] for x in range(0, len(enc_pwd), 2)]
    cleartext = [chr(xlat[index+i] ^ int(pwd_hex[i], 16)) for i in range(0, len(pwd_hex))]

    print("Result: %s" % ''.join(cleartext))


if __name__ == "__main__":
    parser = OptionParser()

    parser.add_option("-p", "--pcfvar", dest="pcfvar", action="store",
                      help="enc_GroupPwd Variable", type="string")

    parser.add_option("-f", "--pcffile", dest="pcffile", action="store",
                      help=".pcf File", type="string")

    parser.add_option("-t", "--type7", dest="type7", action="store",
                      help="Type 7 Password", type="string")

    (options, args) = parser.parse_args()

    if options.pcfvar:
        pcf_decrypt(options.pcfvar)
    elif options.pcffile:
        pcf_parser(options.pcffile)
    elif options.type7:
        type7_decrypt(options.type7)

    else:
        parser.print_help()
        exit(-1)
