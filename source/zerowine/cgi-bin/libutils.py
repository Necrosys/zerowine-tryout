#!/usr/bin/python

import os
import sys
import cgi
import string

from random import *

def isCgiMode():
	gateway = os.getenv("GATEWAY_INTERFACE")
	
	if gateway != None and gateway != "":
		return True
	else:
		return False

def dieError(msg):
	if isCgiMode():
		print "<font color='red'>FATAL: %s</font>" % cgi.escape(msg)
	else:
		print msg
	sys.exit(0)

def printHeader():
	print "Content-Type: text/html\n"

def showWarning(msg):
	if isCgiMode():
		warning = """<br /><table>
<tr>
<td><img src='/img/warning.png' alt="Warning" /></td>
<td><b>Warning:</b> %s</td>
</tr>
</table>""" % cgi.escape(msg)
	else:
		warning = "Warning: %s" % msg

	print warning
	return msg

"""Given a buffer
Check the "file type" using the magic module
Return a descriptive string of the detected type, or None
"""
def buffertype(buffer):
	import magic
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.buffer(buffer)
	ms.close()
	return type

"""Given a filepath
Check the "file type" using the magic module
Return a descriptive string of the detected type, or None
"""
def filetype(str):
	import magic
	ms = magic.open(magic.MAGIC_NONE)
	ms.load()
	type = ms.file(str)
	ms.close()
	return type

"""Given filename and optional contents of file
Return "clean" name, with extension based on filetype detection
"""
def cleanFile(str,buffer=None):
	import re
	# by default, assume exe
	extension = 'exe'
	# preserve extension if filename has one
	parts = re.split("[.]",str)
	if len(parts) > 1:
		extension = parts[-1]
	else:
		# or assume exe if no extension
		extension = 'exe'
	# if buffer not empty, then guess based on content
	if buffer != None:
		type = buffertype(buffer)
		# detect PDF
		if type[0:12] == 'PDF document':
			extension = 'pdf'
		# detection EXE
		elif type[0:17] == 'MS-DOS executable':
			extension = 'exe'
	return "malware." + extension

# Avoid some tricks
def execFile(str):
	return "%s.exe" % ("".join(choice(string.ascii_letters + string.digits) for x in range(randint(1, 8))))

def getJavascript():
	return """<script type="text/javascript">
function toggleShowHide(obj)
{
	var rep;
	rep = document.getElementById(obj);
	
	if (rep.style.display == "block")
	{
		rep.style.display = "none";
		rep.style.visibility="hidden";
	}
	else
	{
		rep.style.display="block";
		rep.style.visibility="visible";
	}
}
</script>
"""

def getCSS():
	return "<link rel='stylesheet' href='/style.css' type='text/css' />"
	
def printBodyHeader():
	print """<!DOCTYPE html>
<html>
<head>
<title></title>
<meta charset="utf-8" />
%s%s
</head>
<body>
<table>
<tr>
<td>""" % (getJavascript(), getCSS())

def printBodyDiv(divId, divData):
	print """<div id='%s' style="visibility:hidden;display:none;">""" % divId
	print "<textarea cols='150' rows='40'>"
	
	print cgi.escape(divData)
	
	print "</textarea>"
	print "</div>"

def printBody(report, headers, strings, signatures, diff, pdfJavaScript, pdfAnalysis):
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
		print """<a href="javascript:toggleShowHide('divReport')"><img src="/img/report.png" height="16" width="16"> Report</a>"""
		print "</td>"

	print "<td>"
	print """<a href="javascript:toggleShowHide('divHeaders');"><img src="/img/headers.png" height="16" width="16"> File headers</a>"""
	print "</td>"

	print "<td>"
	print """<a href="javascript:toggleShowHide('divStrings')"><img src="/img/strings.png" height="16" width="16"> File strings</a>"""
	print "</td>"

	if len(signatures) > 0:
		print "<td>"
		print """<a href="javascript:toggleShowHide('divSignatures')"><img src="/img/signature.png" height="16" width="16"> Signatures</a>"""
		print "</td>"

	if diff != " ":
		print "<td>"
		print """<a href="javascript:toggleShowHide('divDifferences')"><img src="/img/report.png" height="16" width="16"> Differences</a>"""
		print "</td>"

	if pdfJavaScript != " ":
		print "<td>"
		print """<a href="javascript:toggleShowHide('divPdfJavaScript')"><img src="/img/strings.png" height="16" width="16"> PDF JavaScript</a>"""
		print "</td>"

	if pdfAnalysis != "":
		print "<td>"
		print """<a href="javascript:toggleShowHide('divPdfAnalysis')"><img src="/img/strings.png" height="16" width="16"> PDF Analysis</a>"""
		print "</td>"

	print "</tr><tr><td colspan='%s'><br />" % (colspan)
	
	#print "<img src='/img/analyzing.jpg'/>"
	print "</td></tr>"
	print "<tr><td colspan='%s'>" % (colspan)
	
	# Report
	if report != " ":
		printBodyDiv("divReport", report)
	
	# File headers
	printBodyDiv("divHeaders", headers)
	
	# File strings
	printBodyDiv("divStrings", strings)
	
	# Signatures
	if len(signatures) > 0:
		printBodyDiv("divSignatures", signatures)
	
	# Differences
	if diff != " ":
		printBodyDiv("divDifferences", diff)
	
	# PDF JavaScript
	if pdfJavaScript != " ":
		printBodyDiv("divPdfJavaScript", pdfJavaScript)

	# PDF Analysis
	if pdfAnalysis != "":
		printBodyDiv("divPdfAnalysis", pdfAnalysis)
	
	print "</td></tr>"
	
	return colspan

def printBodyFooter():
	print """</tr>
</table>
</body>
</html>"""

def isCleanFile(the_file):
	for c in the_file:
		if not c.isalnum():
			if c not in [".", "-", "_"]:
				return False
	return True

def isCleanDir(the_file):
	for c in the_file:
		if not c.isalnum():
			if c not in ["-", "_"]:
				return False
	return True
