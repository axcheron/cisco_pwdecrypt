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

    ht = bin_str[0:20]
    enc = bin_str[40:]
    iv = bin_str

    new_ht = ""
    for i in range(20):
        if i == 19:
            new_ht += chr(ord(ht[19]) + 1)
        else:
            new_ht += ht[i]

    new_ht2 = ""
    for i in range(20):
        if i == 19:
            new_ht2 += chr(ord(ht[19]) + 3)
        else:
            new_ht2 += ht[i]

    hash1 = hashlib.sha1()
    hash1.update(new_ht)
    h2 = hash1.digest()

    hash2 = hashlib.sha1()
    hash2.update(new_ht2)
    h3 = hash2.digest()

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