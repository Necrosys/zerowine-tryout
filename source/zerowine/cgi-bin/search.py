#!/usr/bin/python

import os
import cgi
import sys

from libutils import *
from config import *
from libmalware import *

def searchGeneric(hash, phrase, filename):
	dirName = SAMPLE_DIR + os.sep + hash
	if not os.path.isfile(dirName + os.sep + filename):
		return 0
	text = readFile(dirName, filename)
	return text.count(phrase)

# given a hash and a search phrase
# returns number of matches found
def searchStrings(hash, phrase):
	return searchGeneric(hash, phrase, FILE_STRING_FILENAME)

def searchHashes(hash, phrase):
	return searchGeneric(hash, phrase, FILE_HASH_FILENAME)

def searchHeader(hash, phrase):
	return searchGeneric(hash, phrase, FILE_HEADER_FILENAME)

def searchPDFAnalysis(hash, phrase):
	return searchGeneric(hash, phrase, FILE_PDF_ANALYSIS_FILENAME)

def searchPDFJavascript(hash, phrase):
	return searchGeneric(hash, phrase, FILE_PDF_JAVASCRIPT_ORIG_FILENAME)

def searchTrickDebug(hash, phrase):
	return searchGeneric(hash, phrase, TRICK_DEBUG_FILENAME)

def searchTrickVM(hash, phrase):
	return searchGeneric(hash, phrase, TRICK_VM_FILENAME)

def searchDiff(hash, phrase):
	return searchGeneric(hash, phrase, DIFF_FILENAME)

def searchTags(hash, phrase):
	return searchGeneric(hash, phrase, TAGS_FILENAME)

def viewResult(phrase, results):
	# print search header: search phrase, TODO:time took to search, TODO:number of samples searched
	print '<h1>Search Results</h1>'
	print '<h2>Search Phrase: "' + phrase + '"</h2>'
	print '<p>Number of results: %d</p>' % len(results)
	# if results isempty, then return
	if len(results) <= 0:
		return
	print "<table border=1 cellspacing=2>"
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
		print '<td><a href="/cgi-bin/view.py?hash=' + result[0] + '">' + result[0] + "</a></td>"
		print "</tr>"
	print "</table>"

	return



cgiParameters = cgi.FieldStorage()

# Check to see that we have our required parameters
if cgiParameters.has_key("search"):
	item = cgiParameters["search"]

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
		for hash in hashes:
			# for each analysis type
			num_match = searchStrings(hash, phrase)
			# if searchX == 1 then results.append( [ sample name, analysis type that matched, number of matches ] )
			if num_match > 0:
				results.append( [ hash, 'Strings', num_match ] )
			num_match = searchHashes(hash, phrase)
			if num_match > 0:
				results.append( [ hash, 'Hashes', num_match ] )
			num_match = searchHeader(hash, phrase)
			if num_match > 0:
				results.append( [ hash, 'Header', num_match ] )
			num_match = searchPDFAnalysis(hash, phrase)
			if num_match > 0:
				results.append( [ hash, 'PDF Analysis', num_match ] )
			num_match = searchPDFJavascript(hash, phrase)
			if num_match > 0:
				results.append( [ hash, 'PDF Javascript', num_match ] )
			num_match = searchTrickDebug(hash, phrase)
			if num_match > 0:
				results.append( [ hash, 'Debug Tricks', num_match ] )
			num_match = searchTrickVM(hash, phrase)
			if num_match > 0:
				results.append( [ hash, 'VM Tricks', num_match ] )
			num_match = searchDiff(hash, phrase)
			if num_match > 0:
				results.append( [ hash, 'Diff', num_match ] )
			num_match = searchTags(hash, phrase)
			if num_match > 0:
				results.append( [ hash, 'Tags', num_match ] )

		# show results
		printHeader()
		printBodyHeader()
		viewResult(phrase, results)
		printBodyFooter()

		sys.exit(0)

# if error
printHeader()
print "<H1>Error</H1>"
print "No search string given."

