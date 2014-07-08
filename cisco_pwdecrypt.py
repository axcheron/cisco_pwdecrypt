import pyDes
import hashlib
import binascii
import getopt
import sys
import re


def usage():
    print "Usage: cisco_pwdecrypt.py [options]\n"
    print "Options:"
    print "	[-p, --pcfvar] enc_GroupPwd Variable"
    print "	[-f, --pcffile] .pcf File"

    print "	[-h, --help] Display this menu"


def args_parser():
    arguments = {'help': False, 'pcfvar': '', 'pcffile': ''}

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:f:",
                                   ["help", "pcfvar=", "pcffile="])
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

        else:
            assert False, "Unhandled option"

    return arguments


def pcf_parser(filename):
    hfile = open(filename, 'r')
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


def main():
    args = args_parser()

    if args['help']:
        usage()
        sys.exit(0)

    elif args['pcfvar']:
        pcf_decrypt(args['pcfvar'])

    elif args['pcffile']:
        pcf_parser(args['pcffile'])

    else:
        print "Try 'cisco_pwdecrypt.py --help' for more information."


if __name__ == "__main__":
    main()