#!/usr/bin/python

import cgi
import time

from config import *
from libutils import *
from libmalware import *

def analyze(item, timeout, memory, version, subitem, tags):
	printBodyHeader()

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
	saveAsFile("\n".join(tags), dirName, TAGS_FILENAME)

	# HTML output

	colspan = printBody(report, headers, strings, signatures, diff, pdfJavaScript, pdfAnalysis)
	
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
