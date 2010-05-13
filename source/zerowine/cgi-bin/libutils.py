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
		print "<font color='red'>%s</font>" % cgi.escape(msg)
	else:
		print msg
	sys.exit(0)

def printHeader():
	print "Content-Type: text/html\n\n"

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

def cleanFile(str):
	return "malware.exe"

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

function toggleShowReport()
{
	toggleShowHide('divData');
}

function toggleShowStrings()
{
	toggleShowHide('divStrings');
}

function toggleShowHeaders()
{
	toggleShowHide('divHeaders');
}

function toggleShowSignature()
{
	toggleShowHide('divSignatures');
}
function toggleShowDifference()
{
	toggleShowHide('divDifferences');
}
function toggleShowPdfJavaScript()
{
	toggleShowHide('divPdfJavaScript');
}
function toggleShowPdfAnalysis()
{
	toggleShowHide('divPdfAnalysis');
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
<td>
""" % (getJavascript(), getCSS())

def printBodyFooter():
	print """
</tr>
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
