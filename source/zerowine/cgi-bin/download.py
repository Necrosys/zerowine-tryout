#!/usr/bin/python

import os
import cgi
import sys

from config import SAMPLE_DIR
from libutils import printHeader, dieError, isCleanFile, isCleanDir
from libzip import createArchive, dirEntries
from libmalware import generateHash

def downloadZip(hash):
	dirName = SAMPLE_DIR + os.sep + hash.lower()
	zipName = SAMPLE_DIR + os.sep + hash.lower() + ".zip"

	if not isCleanDir(hash) or not os.path.exists(dirName):
		printHeader()
		dieError("Invalid hash.")
		sys.exit(0)

	createArchive(dirEntries(dirName, True), zipName, hash.lower())

	print "Content-type: application/x-zip-compressed"
	print 'Content-Disposition: attachment; filename="%s.zip"' % hash.lower()
	print
	print file(zipName, "rb").read()

cgiParameters = cgi.FieldStorage()

# Check to see that we have our required parameters
if cgiParameters.has_key("fileName"):
	item = cgiParameters["fileName"]
	
	if item.filename and not item.filename == "":
		data = item.file.read()
		hashes = generateHash(data)

		# hashes[-1] = SHA-512
		downloadZip(hashes[-1])
		sys.exit(0)

if (cgiParameters.has_key("hash") and cgiParameters.has_key("dump")):
	hash = cgiParameters.getvalue("hash")
	dump = cgiParameters.getvalue("dump")

	dirName = SAMPLE_DIR + os.sep + hash.lower()

	if not isCleanDir(hash) or not os.path.exists(dirName):
		printHeader()
		dieError("Invalid hash.")
		sys.exit(0)

	if not isCleanFile(dump):
		printHeader()
		dieError("Invalid filename.")
		sys.exit(0)

	print "Content-type: application/octet-stream"
	print 'Content-Disposition: attachment; filename="%s"' % dump
	print
	print file(dirName + os.sep + dump, "rb").read()

	sys.exit(0)

elif cgiParameters.has_key("hash"):
	hash = cgiParameters.getvalue("hash")

	downloadZip(hash)
	sys.exit(0)

else:
	print "Content-Type: text/html"
	print
	print "<H1>Error</H1>"
	print "No hash or file given."
