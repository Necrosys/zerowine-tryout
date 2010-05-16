#!/usr/bin/python

import cgi
import time

from config import *
from libutils import *
from libmalware import *

def analyze(item, timeout, memory, version, subitem):
	printBodyHeader()

	print
	print "<h1>Sample analysis result</h1>" 
	print "Original file name: <b>%s</b>" % cgi.escape(item.filename)
	print "<br />"

	startTime = time.ctime()

	msg, dirName, fileName, execfileName, hashes, warnings, diff = analyzeMalware(item, timeout, memory, version, subitem)

	dirName = SAMPLE_DIR + os.sep + dirName

	idx = -1
	for line in msg:
		idx += 1
		if line.find("Starting process") > -1 and line.find(execfileName) > -1:
			lines = msg[idx:]
			break

	headers = getHeaders(fileName)

	unpackFile(headers, fileName)
	stringList = getStrings(fileName)
	strings = "".join(stringList)

	pdfJavaScript = "".join(getPdfJavaScript(stringList))
	pdfAnalysis = getPdfAnalysis(headers, fileName)

	report = "".join(msg[idx:])
	signatures = analyzeCalls(msg[idx:])
	if len(signatures) > 0:
		signatures.append("End of signature. See report for more information.")
	signatures = "\n".join(signatures)

	try:
		diff.append("\nEnd of difference. Use download function for more information.")
	except:
		pass
	diff = "".join(diff)

	showDumps(dirName, printHTML=False)

	debuggingtricks = showDebuggingTricks(msg, printHTML=False)
	vmtricks = showVMDetectionTricks(fileName, dirName, printHTML=False)

	finishTime = time.ctime()

	# Save as file

	saveAsFile(item.filename, dirName, FILE_NAME_ORIG_FILENAME)
	saveAsFile(execfileName, dirName, FILE_NAME_EXEC_FILENAME)
	saveAsFile("\n".join(hashes), dirName, FILE_HASH_FILENAME)
	saveAsFile(headers, dirName, FILE_HEADER_FILENAME)
	saveAsFile(strings, dirName, FILE_STRING_FILENAME)
	saveAsFile(pdfJavaScript, dirName, FILE_PDF_JAVASCRIPT_ORIG_FILENAME)
	saveAsFile(pdfAnalysis, dirName, FILE_PDF_ANALYSIS_FILENAME)

	saveAsFile(report, dirName, REPORT_FILENAME)
	saveAsFile(signatures, dirName, REPORT_SIGNATURE_FILENAME)
	saveAsFile("\n".join(warnings), dirName, REPORT_WARNING_FILENAME)

	saveAsFile(diff, dirName, DIFF_FILENAME)

	saveAsFile("\n".join(debuggingtricks), dirName, TRICK_DEBUG_FILENAME)
	saveAsFile("\n".join(vmtricks), dirName, TRICK_VM_FILENAME)

	saveAsFile(startTime, dirName, ANALYZE_START_FILENAME)
	saveAsFile(finishTime, dirName, ANALYZE_FINISH_FILENAME)

	# HTML output

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
	if msg != " ":
		print """<tr><td colspan='%s'>""" % (colspan)
		print """<div><br />Debugger detection tricks:<br /><br /></div>"""
		print """</td></tr>"""
		print """<tr><td colspan='%s'>""" % (colspan)
		
		showDebuggingTricks(msg)
		
		print """</td></tr>"""
	
	# Virtual Machine detection tricks
	print """<tr><td colspan='%s'>""" % (colspan)
	print """<div><br />Virtual Machine detection tricks:<br /><br /></div>"""
	print """</td></tr>"""
	print """<tr><td colspan='%s'>""" % (colspan)
	
	showVMDetectionTricks(fileName, dirName)
	
	print """</td></tr></table>"""
	print """</div>"""
	
	print "<br />"

	print "<br /><div>Analyze started at %s</div>" % (startTime)
	print "<div>Analyze finished at %s</div>" % (finishTime)
	
	printBodyFooter()
