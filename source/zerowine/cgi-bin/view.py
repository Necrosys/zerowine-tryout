#!/usr/bin/python

import os
import cgi
import sys

import libhash

from libutils import *
from config import *
from libmalware import *

def viewResult(dirName):
	# Read file

	finishTime = readFile(dirName, ANALYZE_FINISH_FILENAME)
	if finishTime == " ":
		dieError("Analysis not finished yet. Please try again later.")
	startTime = readFile(dirName, ANALYZE_START_FILENAME)

	origFileName = readFile(dirName, FILE_NAME_ORIG_FILENAME)
	hashes = readFile(dirName, FILE_HASH_FILENAME)
	headers = readFile(dirName, FILE_HEADER_FILENAME)
	pdfAnalysis = readFile(dirName, FILE_PDF_ANALYSIS_FILENAME)
	strings = readFile(dirName, FILE_STRING_FILENAME)
	pdfJavaScript = readFile(dirName, FILE_PDF_JAVASCRIPT_ORIG_FILENAME)
	fileSize = readFile(dirName, FILE_SIZE_FILENAME)

	report = readFile(dirName, REPORT_FILENAME)
	signatures = readFile(dirName, REPORT_SIGNATURE_FILENAME)
	warnings = readFile(dirName, REPORT_WARNING_FILENAME)

	diff = readFile(dirName, DIFF_FILENAME)

	debuggingtricks = readFile(dirName, TRICK_DEBUG_FILENAME)

	tags = readFile(dirName, TAGS_FILENAME)

	printBodyHeader()

	# HTML output

	print "<h1>Sample analysis result</h1>" 
	print "Original file name: <b>%s</b>" % cgi.escape(origFileName)
	print "<br />File size: %s bytes<br />" % fileSize

	hashes = hashes.split("\n")
	# DIRTY HACK
	hashes.sort(key = len)
	hashMD5, hashSHA1, hashSHA224, hashSHA256, hashSHA384, hashSHA512 = hashes
	tags = tags.split("\n")
	
	# XSS protection
	escapedTags = []
	for tag in tags:
		tag = cgi.escape(tag)
		escapedTags.append(tag)

	print "<br />Tags: <b>%s</b><br />" % "</b>, <b>".join(escapedTags)
	print "<br />MD5: %s<br />" % hashMD5
	print "SHA-1: %s<br />" % hashSHA1
	print "SHA-224: %s<br />" % hashSHA224
	print "SHA-256: %s<br />" % hashSHA256
	print "SHA-384: %s<br />" % hashSHA384
	print "SHA-512: %s<br />" % hashSHA512

	if len(warnings) > 1:
		showWarning(warnings)
		showWarning("One or more spawned processes crashed while running!")

	colspan = printBody(report, headers, strings, signatures, diff, pdfJavaScript, pdfAnalysis)

	# Dumps
	print """<tr><td colspan='%s'>""" % (colspan)
	print """<div><br />Dumps:<br /><br /></div>"""
	print """</td></tr>"""
	print """<tr><td colspan='%s'>""" % (colspan)
	
	showDumps(dirName)
	
	print "</td></tr>"
	
	# Debugger detection tricks
	if debuggingtricks != " ":
		print """<tr><td colspan='%s'>""" % (colspan)
		print """<div><br />Debugger detection tricks:<br /><br /></div>"""
		print """</td></tr>"""
		print """<tr><td colspan='%s'>""" % (colspan)
		
		showDebuggingTricks(debuggingtricks.split("\n"))
		
		print """</td></tr>"""
	
	# Virtual Machine detection tricks
	print """<tr><td colspan='%s'>""" % (colspan)
	print """<div><br />Virtual Machine detection tricks:<br /><br /></div>"""
	print """</td></tr>"""
	print """<tr><td colspan='%s'>""" % (colspan)
	
	showVMDetectionTricks(TRICK_VM_FILENAME, dirName)
	
	print """</td></tr></table>"""
	print """</div>"""
	
	print "<br />"

	print "<br /><div>Analyze started at %s</div>" % (startTime)
	print "<div>Analyze finished at %s</div>" % (finishTime)
	
	printBodyFooter()

printHeader()

# Check sample directory
if os.access(SAMPLE_DIR, os.R_OK) == False:
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

		dirName = SAMPLE_DIR + os.sep + hash

		if not isCleanDir(hash) or not checkDir(dirName):
			dieError("Invalid file.")

		viewResult(dirName)
		sys.exit(0)

if cgiParameters.has_key("hash"):
	hash = cgiParameters.getvalue("hash")

	dirName = SAMPLE_DIR + os.sep + hash.lower()

	if hash == "" or not isCleanDir(hash) or not checkDir(dirName):
		dieError("Invalid hash.")

	viewResult(dirName)
	sys.exit(0)

else:
	print "No hash or file given."
