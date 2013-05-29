#!/usr/bin/python

import os
import cgi
import sys

import libhash

from config import SAMPLE_DIR, DEFAULT_HASH_ALGORITHM
from libutils import printHeader, dieError, isCleanFile, isCleanDir
from libzip import createArchive, dirEntries
from libmalware import checkDir

def downloadZip(hash):
	dirName = SAMPLE_DIR + os.sep + hash.lower()
	zipName = SAMPLE_DIR + os.sep + hash.lower() + ".zip"

	if not isCleanDir(hash) or not checkDir(hash.lower()):
		printHeader()
		dieError("Invalid hash.")

	createArchive(dirEntries(dirName, True), zipName, hash.lower())

	print "Content-type: application/x-zip-compressed"
	print 'Content-Disposition: attachment; filename="%s.zip"' % hash.lower()
	print
	print file(zipName, "rb").read()

# Check sample directory
if os.access(SAMPLE_DIR, os.R_OK + os.W_OK) == False:
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

		hash = hashes[DEFAULT_HASH_ALGORITHM]

		downloadZip(hash)
		sys.exit(0)

if (cgiParameters.has_key("hash") and cgiParameters.has_key("dump")):
	hash = cgiParameters.getvalue("hash")
	dump = cgiParameters.getvalue("dump")

	dirName = SAMPLE_DIR + os.sep + hash.lower()

	if not isCleanDir(hash) or not checkDir(hash.lower()):
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
	hash = cgiParameters.getvalue("hash")

	## If you want, you can comment out these lines
	if hash == "":
		printHeader()
		dieError("Invalid hash.")
	##

	downloadZip(hash)
	sys.exit(0)

else:
	printHeader()
	print "No hash or file given."
