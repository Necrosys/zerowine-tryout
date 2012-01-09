#!/usr/bin/env python

import sys
import pefile

def main(filename):
    pe = pefile.PE(filename, fast_load=True)

    if pe.FILE_HEADER.Characteristics & 0x2000 != 0:
        return 0
    else:
        return 1

def usage():
    print "Usage:", sys.argv[0], "<PE file>"

if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
        sys.exit(1)
    else:
        sys.exit(main(sys.argv[1]))
