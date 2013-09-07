#!/usr/bin/python
#
# To add a new search type, create a new function like below
# and call it after the
#     if not types or "all" in types:
# line, like the others
#         num_match = yourfunction(hash, phrase)
#         if num_match > 0:
#             results.append( [ hash, 'UNIQUE DESCRIPTIVE NAME', num_match ] )
# remembering to create a UNIQUE DESCRIPTIVE NAME.
#

import os
import cgi
import sys

from libutils import *
from config import *
from libmalware import *


#############################################################
# given a hash, search phrase, and filename to search within
# return number of matches found
def searchGeneric(fileHash, phrase, filename):
    dirName = SAMPLE_DIR + os.sep + fileHash
    if not os.path.isfile(dirName + os.sep + filename):
        return 0
    text = readFile(dirName, filename)
    return text.count(phrase)

#############################################################


def searchStrings(fileHash, phrase):
    return searchGeneric(fileHash, phrase, FILE_STRING_FILENAME)


def searchHashes(fileHash, phrase):
    return searchGeneric(fileHash, phrase, FILE_HASH_FILENAME)


def searchHeader(fileHash, phrase):
    return searchGeneric(fileHash, phrase, FILE_HEADER_FILENAME)


def searchPDFAnalysis(fileHash, phrase):
    return searchGeneric(fileHash, phrase, FILE_PDF_ANALYSIS_FILENAME)


def searchPDFJavascript(fileHash, phrase):
    return searchGeneric(fileHash, phrase, FILE_PDF_JAVASCRIPT_ORIG_FILENAME)


def searchTrickDebug(fileHash, phrase):
    return searchGeneric(fileHash, phrase, TRICK_DEBUG_FILENAME)


def searchTrickVM(fileHash, phrase):
    return searchGeneric(fileHash, phrase, TRICK_VM_FILENAME)


def searchDiff(fileHash, phrase):
    return searchGeneric(fileHash, phrase, DIFF_FILENAME)


def searchTags(fileHash, phrase):
    return searchGeneric(fileHash, phrase, TAGS_FILENAME)


def viewResult(phrase, results):
    # print search header: search phrase, TODO:time took to search, TODO:number of samples searched
    print '<h1>Search Results</h1>'
    print '<h2>Search Phrase: "' + cgi.escape(phrase) + '"</h2>' # XSS protection
    print '<p>Number of results: %d</p>' % len(results)
    # if results isempty, then return
    if len(results) <= 0:
        return
    print "<table border=1>"
    print "<tr><th>Hits</th><th>Analysis Type</th><th>Hash</th></tr>"
    # sort results in num_of_matches order
    results.sort(reverse=True, key=lambda match: match[2])
    # foreach results
    for result in results:
        # TODO: print sample name, sample hash as link to full analysis, analysis context
        # hash, type, num_matches
        print "<tr>"
        print "<td>%d</td>" % result[2]
        print "<td>" + result[1] + "</td>"
        print "<td><a href='" + CGI_PATH + "/" + CGI_VIEW_FILENAME + "?hash=" + result[0] + "'>" + result[
            0] + "</a></td>"
        print "</tr>"
    print "</table>"

    return


printHeader()

# Check sample directory
if not os.access(SAMPLE_DIR, os.R_OK):
    dieError("Sample directory does not exist or permission denied.")

cgiParameters = cgi.FieldStorage()

# Check to see that we have our required parameters
if cgiParameters.has_key("search"):
    item = cgiParameters["search"]
    # search only given type(s), default all
    types = cgiParameters.getlist("type")

    # iterate through results, building table of sample names and search contexts
    if item.value and not item.value == "":
        phrase = item.value
        # create empty results array
        results = []

        # get list of samples
        hashes = []
        for fn in os.listdir(SAMPLE_DIR):
            if os.path.isdir(SAMPLE_DIR + os.sep + fn) and not os.path.islink(SAMPLE_DIR + os.sep + fn):
                hashes.append(fn)
                # iterate through samples' analyses
        for fileHash in hashes:
            # for each analysis type
            # if num_match > 0 then results.append( [ sample name, analysis type that matched, number of matches ] )
            if not types or "all" in types or "strings" in types:
                num_match = searchStrings(fileHash, phrase)
                if num_match > 0:
                    results.append([fileHash, 'Strings', num_match])
            if not types or "all" in types or "hashes" in types:
                num_match = searchHashes(fileHash, phrase)
                if num_match > 0:
                    results.append([fileHash, 'Hashes', num_match])
            if not types or "all" in types or "pdfanalysis" in types:
                num_match = searchPDFAnalysis(fileHash, phrase)
                if num_match > 0:
                    results.append([fileHash, 'PDF Analysis', num_match])
            if not types or "all" in types or "pdfanalysis" in types:
                num_match = searchPDFJavascript(fileHash, phrase)
                if num_match > 0:
                    results.append([fileHash, 'PDF Javascript', num_match])
            if not types or "all" in types or "tags" in types:
                num_match = searchTags(fileHash, phrase)
                if num_match > 0:
                    results.append([fileHash, 'Tags', num_match])
            if not types or "all" in types:
                num_match = searchHeader(fileHash, phrase)
                if num_match > 0:
                    results.append([fileHash, 'Header', num_match])
                num_match = searchTrickDebug(fileHash, phrase)
                if num_match > 0:
                    results.append([fileHash, 'Debug Tricks', num_match])
                num_match = searchTrickVM(fileHash, phrase)
                if num_match > 0:
                    results.append([fileHash, 'VM Tricks', num_match])
                num_match = searchDiff(fileHash, phrase)
                if num_match > 0:
                    results.append([fileHash, 'Diff', num_match])

        # show results
        printBodyHeader()
        viewResult(phrase, results)
        printBodyFooter()

        sys.exit(0)

# if error
print "No search string given."
