#!/usr/bin/python

import sys

from tricks import *


def main(the_file):
    try:
        f = file(the_file, "rb")
    except:
        print "Error opening file:", sys.exc_info()[1]
        sys.exit(1)

    buf = f.read()
    f.close()

    tricks = check_tricks(buf)

    if len(tricks) > 0:
        for trick in tricks:
            print "***Detected trick %s" % trick

        print
        print "Total of %d trick(s) detected." % len(tricks)
    else:
        print "No trick detected."


def check_trick_from_file(the_file):
    f = file(the_file, "rb")
    buf = f.read()
    f.close()

    return check_tricks(buf)


def check_tricks(buf):
    tricks = 0
    ret = []
    for trick in DETECTION_TRICKS:
        if buf.find(DETECTION_TRICKS[trick]) > -1:
            ret.append(trick)

    return ret


def usage():
    print "Usage:", sys.argv[0], "<file>"


def banner():
    print "Virtual Machine Trick's Detector v0.1 - Joxean Koret "
    print


if __name__ == "__main__":
    banner()
    if len(sys.argv) == 1:
        usage()
        sys.exit(1)
    else:
        main(sys.argv[1])
