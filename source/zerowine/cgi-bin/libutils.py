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
		warning = """<br><table border="0" cellpading="0" cellspacing="0">
<tr>
<td valign="center"><img src='/img/warning.png'/></td>
<td><font color='red'>Warning:</font> %s</td>
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
	return """
<script>
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
</script>
"""

def getCSS():
	return "<link rel='stylesheet' href='/style.css' type='text/css'>"

def printBodyHeader():
	print """<html><head>%s%s</head><body><table border="0" cellspacing="0" cellpading="0">
<tr>
<td background="/img/p.gif" width="35"></td>
<td background="/img/top.gif" height="35">&nbsp;</td>
<td background="/img/q.gif" width="40" height="35">&nbsp;</td>
</tr>
<tr>
<td background="/img/bg-left.gif"></td>
<td>
""" % (getJavascript(), getCSS())

def printBodyFooter():
	print """<td background="/img/bg-right.gif">&nbsp;</td></td>
</tr><tr>
<td background="/img/b.gif" width="35">&nbsp;</td>
<td background="/img/bg-bottom.gif" height="36" width="35">&nbsp;</td>
<td background="/img/d.gif" width="35">&nbsp;</td>
</tr>
</table></body></html>"""

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
