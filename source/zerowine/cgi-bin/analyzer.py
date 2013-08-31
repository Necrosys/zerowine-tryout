#!/usr/bin/python

import cgi
import time

from config import *
from libutils import *
from libmalware import *

def analyze(item, timeout, memory, version, subitem, tags, unpack):
	printBodyHeader()

	startTime = time.ctime()

	fileName, hashes, fileSize = analyzeStatic(item, subitem)

	fhash = hashes[DEFAULT_HASH_ALGORITHM]
	dirName = SAMPLE_DIR + os.sep + fhash
	lockName = SAMPLE_DIR + os.sep + LOCK_FILENAME

	isRunnable = checkRunnable(timeout, lockName, fileName)

	if isRunnable:
		lockAnalyze(lockName)
		
		msg, execfileName = analyzeDynamic(fileName, timeout, memory, version)
		
		idx = -1
		for line in msg:
			idx += 1
			# If EXE
			if line.find("Starting process") > -1 and line.find(execfileName) > -1:
				break
			# If DLL
			elif line.find("load_native_dll") > -1 and line.find(execfileName) > -1:
				break
	else:
		msg = " "
		idx = 0
		execfileName = " "

	headers = getHeaders(fileName)

	if unpack == "True":
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

	error, warnings = checkRuntimeErrors(msg)

	if error:
		showWarning("One or more spawned processes crashed while running!")

	if isRunnable:
		diff = diffFile(dirName)
	else:
		diff = " "

	tags = autoTag(tags, diff, "diff")

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
	saveAsFile("\n".join(hashes.values()), dirName, FILE_HASH_FILENAME)
	saveAsFile(headers, dirName, FILE_HEADER_FILENAME)
	saveAsFile(strings, dirName, FILE_STRING_FILENAME)
	saveAsFile(pdfJavaScript, dirName, FILE_PDF_JAVASCRIPT_ORIG_FILENAME)
	saveAsFile(pdfAnalysis, dirName, FILE_PDF_ANALYSIS_FILENAME)
	saveAsFile(str(fileSize), dirName, FILE_SIZE_FILENAME)

	saveAsFile(report, dirName, REPORT_FILENAME)
	saveAsFile(signatures, dirName, REPORT_SIGNATURE_FILENAME)
	saveAsFile("\n".join(warnings), dirName, REPORT_WARNING_FILENAME)

	saveAsFile(diff, dirName, DIFF_FILENAME)

	saveAsFile("\n".join(debuggingtricks), dirName, TRICK_DEBUG_FILENAME)
	saveAsFile("\n".join(vmtricks), dirName, TRICK_VM_FILENAME)

	saveAsFile(startTime, dirName, ANALYZE_START_FILENAME)
	saveAsFile(finishTime, dirName, ANALYZE_FINISH_FILENAME)
	saveAsFile("\n".join(tags), dirName, TAGS_FILENAME)

	if isRunnable:
		unlockAnalyze(lockName)
	
	# Result link
	print "<br /><a href='" + CGI_PATH + "/" + CGI_VIEW_FILENAME + "?hash=%s'>View result</a>" % fhash
	print "<br /><br /><a href='" + CGI_PATH + "/" + CGI_DOWNLOAD_FILENAME + "?hash=%s'>Download result</a>" % fhash
	
	printBodyFooter()
