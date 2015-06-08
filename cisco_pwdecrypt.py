import pyDes
import hashlib
import binascii
import getopt
import sys
import re


xlat = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 0x79,
        0x65, 0x77, 0x72, 0x6b, 0x6c,  0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42]


def usage():
    print "Usage: cisco_pwdecrypt.py [options]\n"
    print "Options:"
    print "	[-p, --pcfvar] enc_GroupPwd Variable"
    print "	[-f, --pcffile] .pcf File"
    print "	[-t, --type7] Type 7 Password"

    print "	[-h, --help] Display this menu"


def args_parser():
    arguments = {'help': False, 'pcfvar': '', 'pcffile': '', 'type7': ''}

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:f:t:",
                                   ["help", "pcfvar=", "pcffile=", "type7="])
    except getopt.GetoptError, err:
        print str(err)
        print "Try 'cisco_pwdecrypt.py --help' for more information."
        sys.exit(2)

    for o, a in opts:
        if o in ("-h", "--help"):
            arguments['help'] = True
        elif o in ("-p", "--pcfvar"):
            arguments['pcfvar'] = a
        elif o in ("-f", "--pcffile"):
            arguments['pcffile'] = a
        elif o in ("-t", "--type7"):
            arguments['type7'] = a

        else:
            assert False, "Unhandled option"

    return arguments


def pcf_parser(filename):

    try:
        hfile = open(filename, 'r')
    except Exception, e:
        print e
        sys.exit(0)

    keyword = "enc_GroupPwd="

    for line in hfile.readlines():
        if re.search(keyword, line, flags=0):
            enc = line.strip(keyword)
            pcf_decrypt(enc.rstrip())

    hfile.close()


def pcf_decrypt(hex_str):

    bin_str = binascii.unhexlify(hex_str)
    ht = list(bin_str[0:20])
    enc = bin_str[40:]
    iv = bin_str

    ht[19] = chr(ord(ht[19]) + 1)

    hash = hashlib.sha1()
    hash.update(''.join(ht))
    h2 = hash.digest()

    ht[19] = chr(ord(ht[19]) + 2)

    hash = hashlib.sha1()
    hash.update(''.join(ht))
    h3 = hash.digest()

    key = h2 + h3[0:4]

    h3des = pyDes.triple_des(key, pyDes.CBC, iv[0:8], pad=None, padmode=pyDes.PAD_PKCS5)
    print "Result: %s" % h3des.decrypt(enc)

def type7_decrypt(enc_pwd):

    index = int(enc_pwd[:2])
    enc_pwd = enc_pwd[2:].rstrip()
    pwd_hex = [enc_pwd[x:x + 2] for x in range(0, len(enc_pwd), 2)]
    cleartext = [chr(xlat[index+i] ^ int(pwd_hex[i], 16)) for i in range(0, len(pwd_hex))]

    print "Result: %s" % ''.join(cleartext)


def main():
    args = args_parser()

    if args['help']:
        usage()
        sys.exit(0)

    elif args['pcfvar']:
        pcf_decrypt(args['pcfvar'])

    elif args['pcffile']:
        pcf_parser(args['pcffile'])

    elif args['type7']:
        type7_decrypt(args['type7'])

    else:
        print "Try 'cisco_pwdecrypt.py --help' for more information."


if __name__ == "__main__":
    main()
