#!/usr/bin/python

import os
import cgi
import sys

from libutils import *
from config import *
from libmalware import *

def viewResult(dirName):
	# Read file

	finishTime = readFile(dirName, ANALYZE_FINISH_FILENAME)
	if finishTime == " ":
		printHeader()
		dieError("Analysis not finished yet. Please try again later.")
	startTime = readFile(dirName, ANALYZE_START_FILENAME)

	origFileName = readFile(dirName, FILE_NAME_ORIG_FILENAME)
	hashes = readFile(dirName, FILE_HASH_FILENAME)
	headers = readFile(dirName, FILE_HEADER_FILENAME)
	pdfAnalysis = readFile(dirName, FILE_PDF_ANALYSIS_FILENAME)
	strings = readFile(dirName, FILE_STRING_FILENAME)
	pdfJavaScript = readFile(dirName, FILE_PDF_JAVASCRIPT_ORIG_FILENAME)

	report = readFile(dirName, REPORT_FILENAME)
	signatures = readFile(dirName, REPORT_SIGNATURE_FILENAME)
	warnings = readFile(dirName, REPORT_WARNING_FILENAME)

	diff = readFile(dirName, DIFF_FILENAME)

	debuggingtricks = readFile(dirName, TRICK_DEBUG_FILENAME)

	printHeader()
	printBodyHeader()

	# HTML output

	print
	print "<h1>Sample analysis result</h1>" 
	print "Original file name: <b>%s</b>" % cgi.escape(origFileName)
	print "<br />"

	hashes = hashes.split("\n")
	hashMD5, hashSHA1, hashSHA224, hashSHA256, hashSHA384, hashSHA512 = hashes

	print "<br />MD5: %s<br />" % hashMD5
	print "SHA-1: %s<br />" % hashSHA1
	print "SHA-224: %s<br />" % hashSHA224
	print "SHA-256: %s<br />" % hashSHA256
	print "SHA-384: %s<br />" % hashSHA384
	print "SHA-512: %s<br />" % hashSHA512

	if len(warnings) > 1:
		showWarning(warnings)
		showWarning("One or more spawned processes crashed while running!")

	colspan = 7

	if report == " ":
		colspan = colspan - 1
	if len(signatures) == 0:
		colspan = colspan - 1
	if diff == " ":
		colspan = colspan - 1
	if pdfJavaScript == " ":
		colspan = colspan - 1
	if pdfAnalysis == "":
		colspan = colspan - 1

	print "<br />"
	print "<div>"
	print "General information:<br /><br /><table><tr>"

	if report != " ":
		print "<td>"
		print """<a href="javascript:toggleShowReport()"><img src="/img/report.png" height="16" width="16"> Report</a>"""
		print "</td>"

	print "<td>"
	print """<a href="javascript:toggleShowHeaders()"><img src="/img/headers.png" height="16" width="16"> File headers</a>"""
	print "</td>"

	print "<td>"
	print """<a href="javascript:toggleShowStrings()"><img src="/img/strings.png" height="16" width="16"> File strings</a>"""
	print "</td>"

	if len(signatures) > 0:
		print "<td>"
		print """<a href="javascript:toggleShowSignature()"><img src="/img/signature.png" height="16" width="16"> Signatures</a>"""
		print "</td>"

	if diff != " ":
		print "<td>"
		print """<a href="javascript:toggleShowDifference()"><img src="/img/report.png" height="16" width="16"> Differences</a>"""
		print "</td>"

	if pdfJavaScript != " ":
		print "<td>"
		print """<a href="javascript:toggleShowPdfJavaScript()"><img src="/img/strings.png" height="16" width="16"> PDF JavaScript</a>"""
		print "</td>"

	if pdfAnalysis != "":
		print "<td>"
		print """<a href="javascript:toggleShowPdfAnalysis()"><img src="/img/strings.png" height="16" width="16"> PDF Analysis</a>"""
		print "</td>"

	print "</tr><tr><td colspan='%s'><br />" % (colspan)
	
	#print "<img src='/img/analyzing.jpg'/>"
	print "</td></tr>"
	print "<tr><td colspan='%s'>" % (colspan)
	
	# Report
	if report != " ":
		print """<div id='divData' style="visibility:hidden;display:none;float: center; width: 50%;">"""
		print "<textarea cols='150' rows='40'>"
		
		print cgi.escape(report)
		
		print "</textarea><br />"
		print "</div>"
	
	# File headers
	print """<div id='divHeaders' style="visibility:hidden;display:none;float: center; width: 50%;">"""
	print """<textarea cols='150' rows='40'>"""
	
	print cgi.escape(headers)
	
	print "</textarea>"
	print "</div>"
	
	# File strings
	print """<div id='divStrings' style="visibility:hidden;display:none;float: center; width: 50%;">"""
	print """<textarea cols='150' rows='40'>"""
	
	print cgi.escape(strings)
	
	print "</textarea>"
	print "</div>"
	
	# Signatures
	if len(signatures) > 0:
		print """<div id='divSignatures' style="visibility:hidden;display:none;float: center; width: 50%;">"""
		print """<textarea cols='150' rows='40'>"""
		
		print cgi.escape(signatures)
		
		print "</textarea>"
		print "</div>"
	
	# Differences
	if diff != " ":
		print """<div id='divDifferences' style="visibility:hidden;display:none;float: center; width: 50%;">"""
		print """<textarea cols='150' rows='40'>"""
		
		print cgi.escape(diff)
		
		print "</textarea>"
		print "</div>"
	
	# PDF JavaScript
	if pdfJavaScript != " ":
		print """<div id='divPdfJavaScript' style="visibility:hidden;display:none;float: center; width: 50%;">"""
		print """<textarea cols='150' rows='40'>"""
		
		print cgi.escape(pdfJavaScript)
		
		print "</textarea>"
		print "</div>"
	
	# PDF Analysis
	if pdfAnalysis != "":
		print """<div id='divPdfAnalysis' style="visibility:hidden;display:none;float: center; width: 50%;">"""
		print """<textarea cols='150' rows='40'>"""
		
		print cgi.escape(pdfAnalysis)
		
		print "</textarea>"
		print "</div>"
	
	
	print "</td></tr>"
	
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

cgiParameters = cgi.FieldStorage()

# Check to see that we have our required parameters
if cgiParameters.has_key("fileName"):
	item = cgiParameters["fileName"]

	if item.filename and not item.filename == "":
		data = item.file.read()
		hashes = generateHash(data)

		# hashes[-1] = SHA-512
		dirName = SAMPLE_DIR + os.sep + hashes[-1]

		if not isCleanDir(hashes[-1]) or not os.path.exists(dirName):
			printHeader()
			dieError("Invalid file.")

		viewResult(dirName)
		sys.exit(0)

if cgiParameters.has_key("hash"):
	hash = cgiParameters.getvalue("hash")

	dirName = SAMPLE_DIR + os.sep + hash.lower()

	if not isCleanDir(hash) or not os.path.exists(dirName):
		printHeader()
		dieError("Invalid hash.")

	viewResult(dirName)
	sys.exit(0)

else:
	printHeader()
	print
	print "<H1>Error</H1>"
	print "No hash or file given."
