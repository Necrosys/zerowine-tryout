#!/usr/bin/python

import os
import cgi
import sys

import libhash

from config import SAMPLE_DIR, DEFAULT_HASH_ALGORITHM
from libutils import printHeader, dieError, isCleanFile, isCleanDir
from libzip import createArchive, dirEntries
from libmalware import checkDir


def downloadZip(fileHash):
    dirName = SAMPLE_DIR + os.sep + fileHash.lower()
    zipName = SAMPLE_DIR + os.sep + fileHash.lower() + ".zip"

    if not isCleanDir(fileHash) or not checkDir(dirName):
        printHeader()
        dieError("Invalid hash.")

    createArchive(dirEntries(dirName, True), zipName, fileHash.lower())

    print "Content-type: application/x-zip-compressed"
    print 'Content-Disposition: attachment; filename="%s.zip"' % fileHash.lower()
    print
    print file(zipName, "rb").read()

# Check sample directory
if not os.access(SAMPLE_DIR, os.R_OK + os.W_OK):
    printHeader()
    dieError("Sample directory does not exist or permission denied.")

cgiParameters = cgi.FieldStorage()

# Check to see that we have our required parameters
if cgiParameters.has_key("fileName"):
    item = cgiParameters["fileName"]

    if item.filename and not item.filename == "":
        data = item.file.read()

        libHash = libhash.LibHash()
        libHash.generateHashesFromData(data)

        hashes = libHash.__dict__

        del libHash

        fileHash = hashes[DEFAULT_HASH_ALGORITHM]

        downloadZip(fileHash)
        sys.exit(0)

if cgiParameters.has_key("hash") and cgiParameters.has_key("dump"):
    fileHash = cgiParameters.getvalue("hash")
    dump = cgiParameters.getvalue("dump")

    dirName = SAMPLE_DIR + os.sep + fileHash.lower()

    if not isCleanDir(fileHash) or not checkDir(dirName):
        printHeader()
        dieError("Invalid hash.")

    if not isCleanFile(dump):
        printHeader()
        dieError("Invalid filename.")

    print "Content-type: application/octet-stream"
    print 'Content-Disposition: attachment; filename="%s"' % dump
    print
    print file(dirName + os.sep + dump, "rb").read()

    sys.exit(0)

elif cgiParameters.has_key("hash"):
    fileHash = cgiParameters.getvalue("hash")

    ## If you want, you can comment out these lines
    if fileHash == "":
        printHeader()
        dieError("Invalid hash.")
        ##

    downloadZip(fileHash)
    sys.exit(0)

else:
    printHeader()
    print "No hash or file given."
