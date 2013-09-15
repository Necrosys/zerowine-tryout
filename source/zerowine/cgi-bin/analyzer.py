#!/usr/bin/python
"""
    analyzer
"""

import time
import os
import config
import libutils
import libmalware


def analyze(item, timeout, memory, version, subitem, tags, unpack):
    libutils.printBodyHeader()

    startTime = time.ctime()

    fileName, hashes, fileSize = libmalware.analyzeStatic(item, subitem)

    defaultHash = hashes[config.DEFAULT_HASH_ALGORITHM]
    dirName = config.SAMPLE_DIR + os.sep + defaultHash
    lockName = config.SAMPLE_DIR + os.sep + config.LOCK_FILENAME

    isRunnable = libmalware.checkRunnable(timeout, lockName, fileName)

    if isRunnable:
        libmalware.lockAnalyze(lockName)

        msg, execfileName = libmalware.analyzeDynamic(
            fileName, timeout, memory, version)

        idx = -1
        for line in msg:
            idx += 1
            # If EXE
            if line.find("Starting process") > -1 \
                    and line.find(execfileName) > -1:
                break
            # If DLL
            elif line.find("load_native_dll") > -1 \
                    and line.find(execfileName) > -1:
                break
    else:
        msg = " "
        idx = 0
        execfileName = " "

    headers = libmalware.getHeaders(fileName)

    if unpack == "True":
        libmalware.unpackFile(headers, fileName)

    stringList = libmalware.getStrings(fileName)
    strings = "".join(stringList)

    pdfJavaScript = "".join(libmalware.getPdfJavaScript(stringList))
    pdfAnalysis = libmalware.getPdfAnalysis(headers, fileName)

    report = "".join(msg[idx:])
    signatures = libmalware.analyzeCalls(msg[idx:])
    if len(signatures) > 0:
        signatures.append("End of signature. See report for more information.")
    signatures = "\n".join(signatures)

    error, warnings = libmalware.checkRuntimeErrors(msg)

    if error:
        libutils.showWarning(
            "One or more spawned processes crashed while running!")

    if isRunnable:
        diff = libmalware.diffFile(dirName)
    else:
        diff = " "

    tags = libmalware.autoTag(tags, diff, "diff")

    try:
        diff.append(
            "\nEnd of difference. Use download function for more information.")
    except AttributeError:
        pass
    diff = "".join(diff)

    libmalware.showDumps(dirName, printHTML=False)

    debuggingtricks = libmalware.showDebuggingTricks(msg, printHTML=False)
    vmtricks = libmalware.showVMDetectionTricks(
        fileName, dirName, printHTML=False)

    finishTime = time.ctime()

    # Save as file

    libmalware.saveAsFile(
        item.filename,
        dirName,
        config.FILE_NAME_ORIG_FILENAME)
    libmalware.saveAsFile(
        execfileName,
        dirName,
        config.FILE_NAME_EXEC_FILENAME)
    libmalware.saveAsFile(
        "\n".join(hashes.values()),
        dirName,
        config.FILE_HASH_FILENAME)
    libmalware.saveAsFile(headers, dirName, config.FILE_HEADER_FILENAME)
    libmalware.saveAsFile(strings, dirName, config.FILE_STRING_FILENAME)
    libmalware.saveAsFile(
        pdfJavaScript,
        dirName,
        config.FILE_PDF_JAVASCRIPT_ORIG_FILENAME)
    libmalware.saveAsFile(
        pdfAnalysis,
        dirName,
        config.FILE_PDF_ANALYSIS_FILENAME)
    libmalware.saveAsFile(str(fileSize), dirName, config.FILE_SIZE_FILENAME)

    libmalware.saveAsFile(report, dirName, config.REPORT_FILENAME)
    libmalware.saveAsFile(
        signatures,
        dirName,
        config.REPORT_SIGNATURE_FILENAME)
    libmalware.saveAsFile(
        "\n".join(warnings),
        dirName,
        config.REPORT_WARNING_FILENAME)

    libmalware.saveAsFile(diff, dirName, config.DIFF_FILENAME)

    libmalware.saveAsFile(
        "\n".join(debuggingtricks),
        dirName,
        config.TRICK_DEBUG_FILENAME)
    libmalware.saveAsFile(
        "\n".join(vmtricks),
        dirName,
        config.TRICK_VM_FILENAME)

    libmalware.saveAsFile(startTime, dirName, config.ANALYZE_START_FILENAME)
    libmalware.saveAsFile(finishTime, dirName, config.ANALYZE_FINISH_FILENAME)
    libmalware.saveAsFile("\n".join(tags), dirName, config.TAGS_FILENAME)

    if isRunnable:
        libmalware.unlockAnalyze(lockName)

    # Result link
    print "<br /><a href='" + \
          config.CGI_PATH + "/" + \
          config.CGI_VIEW_FILENAME + \
          "?hash=%s'>View result</a>" % defaultHash
    print "<br /><br /><a href='" + \
          config.CGI_PATH + "/" + \
          config.CGI_DOWNLOAD_FILENAME + \
          "?hash=%s'>Download result</a>" % defaultHash

    libutils.printBodyFooter()
