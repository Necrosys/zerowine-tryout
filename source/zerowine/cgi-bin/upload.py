#!/usr/bin/python

import sys
import cgi

from config import *
from libutils import *
from analyzer import *

form = cgi.FieldStorage()

if not form:
	printHeader()
	dieError("Bad arguments.")
else:
	printHeader()

	# Check sample directory
	if os.access(SAMPLE_DIR, os.R_OK + os.W_OK) == False:
		dieError("Sample directory does not exist or permission denied.")

	if not form.has_key("fileName"):
		dieError("No file name.")

	item = form["fileName"]

	tags = []
	if form.has_key("tags"):
		tags = form.getvalue("tags").strip()
		if len(tags) > 0:
			tags = [tag.strip() for tag in tags.split(",")]

	if form.has_key("subfileName"):
		subitem = form["subfileName"]
	else:
		subitem = ""

	if not item.file or item.filename == "" or not item.filename:
		dieError("Empty file given.")

	if not form.has_key("timeout"):
		timeout = 0
		showWarning("No timeout specified, disabling dynamic analyzer")
	else:
		try:
			timeout = int(form.getvalue("timeout"))
		except:
			dieError("Invalid timeout: %s" % str(sys.exc_info()[1]))

	if timeout < MIN_TIMEOUT:
		timeout = 0
		showWarning("Too small timeout specified, disabling dynamic analyzer")

	if timeout > MAX_TIMEOUT:
		timeout = MAX_TIMEOUT # Do not allow too big timeouts
		showWarning("Too big timeout specified, using maximum %d" % timeout)

	if not form.has_key("memory"):
		memory = 0
	else:
		try:
			memory = int(form.getvalue("memory"))
		except:
			dieError("Invalid dump memory timeout: %s" % str(sys.exc_info()[1]))

	if memory < 0:
		memory = 0
		showWarning("Too small dump memory timeout specified, disabled")

	if memory > timeout:
		memory = timeout
		showWarning("Too big dump memory timeout specified, using maximum %d" % memory)

	if not form.has_key("version"):
		version = "winxp"
	else:
		version = form.getvalue("version")

	if not form.has_key("unpack"):
		unpack = "False"
	else:
		unpack = form.getvalue("unpack")

	analyze(item, timeout, memory, version, subitem, tags, unpack)
	
