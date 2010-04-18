#!/usr/bin/python

import os
import sys
import time

from ptrace.debugger.debugger import PtraceDebugger

def extractFileName(base_file):
	pos = base_file.find("\\")
	
	if pos > -1:
		rbase_file = base_file[::-1]
		pos = rbase_file.find("\\")
		return base_file[len(base_file)-pos:]
	else:
		return os.path.basename(base_file)
	
def dumpSegment(f_in, f_out, segment):
	""" Dump a segment of memory """
#	print "*** Dumping from 0x%x to 0x%x" % (segment[0], segment[1])
	start_pos = segment[0]
	end_pos   = segment[1]
	pos       = start_pos


	if end_pos - start_pos > 1024*1024*50:
#		print "*** Memory chunk bigger than 50 MB, ignored..."
		return

	f_in.seek(start_pos)

	while pos <= end_pos:
		c = f_in.read(1)
		f_out.write(c)
		pos += 1

def dumpProcessMemory(pid, out_file, segments):
	""" Dump every segment of the process """
	
	f_in  = file("/proc/%d/mem" % pid, "rb")
	f_out = file(out_file, "wb")
	
	i = 0
	for segment in segments:
		i += 1
		dumpSegment(f_in, f_out, segment)
	
	f_out.close()
	f_in.close()

def cleanCmdLine(name):
	
	""" Delete the first '.' and '/' symbols and the leading 0x00 chars """
	buf = ""
	
	for c in name:
		if c == "\x00":
			continue
		
		if c in ["/", "."]:
			if buf == "":
				continue
			else:
				buf += c
		else:
			buf += c
	
	return buf

def getProcessName(pid):
	""" Extract the program's name to dump """
	f = file("/proc/%d/cmdline" % pid, "r")
	name = cleanCmdLine(f.read())
	f.close()

	return name

def getAddressFromLine(line):
	""" Extract the start_address and end_address from a line with the format of
		the file /proc/PID/smaps """
	chunk = line.split(" ")[0].split("-")
	start_address = int(chunk[0], 16)
	end_address   = int(chunk[1], 16)
	
	return [start_address, end_address]

def advanceLines(f, lines):
	""" Advanced #<lines> of lines in file <f> """
	for i in xrange(lines): f.readline()

def getMemorySegments(pid):
	""" Returns a list of [start_address, end_address] of the memory chunks """
	name = getProcessName(pid)
	name = extractFileName(name)
#	print "*** Searching for process '%s'" % name
	maps = []

	f = file("/proc/%d/smaps" % pid, "r")
	process_found = False

	while 1:
		line = f.readline()
		if not line:
			break
		
		line = line.strip("\n").strip("\r")
		
		if not process_found and line.find(name) == -1:
			continue
		elif not process_found and line.find(name) > -1:
			process_found = True
			address = getAddressFromLine(line)
			maps.append(address)
			advanceLines(f, 6) # Ignore the next 7 lines
		elif process_found:
			fields = line.split(" ")
			
			if len(fields) > 6: # Another process
				process_found = False
				continue
			
			address = getAddressFromLine(line)
			maps.append(address)
			advanceLines(f, 7) # Ignore the next 6 lines

	f.close()

	return maps

def main(pid, out_file):
	""" Attach to the process, dump the memory and detach from it """
	dbg = PtraceDebugger()
	dbg.addProcess(pid, False)
	segments = getMemorySegments(pid)
	dumpProcessMemory(pid, out_file, segments)
	dbg.quit()

def usage():
	""" Show usage information """
	print "Usage:", sys.argv[0], "<pid> <output file>"
	print

if __name__ == "__main__":
#	print sys.argv
	if len(sys.argv) != 3:
		usage()
		sys.exit(1)
	
	main(int(sys.argv[1]), sys.argv[2])
