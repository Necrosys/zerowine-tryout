#!/usr/bin/python

"""
Zerowine Multiuser Version (2.0)
Copyright (c) 2009, Joxean Koret
All rights Reserved
"""

import os
import sys

from ptrace.debugger.debugger import PtraceDebugger


def extractFileName(base_file):
    pos = base_file.find("\\")

    if pos > -1:
        rbase_file = base_file[::-1]
        pos = rbase_file.find("\\")
        return base_file[len(base_file) - pos:]
    else:
        return os.path.basename(base_file)


def dumpSegment(f_in, f_out, segment, debug=True):
    """ Dump a segment of memory """

    debug = False
    if debug:
        print "*** Dumping from 0x%x to 0x%x" % (segment[0], segment[1])

    start_pos = segment[0]
    end_pos = segment[1]
    pos = start_pos

    if start_pos >= 0x7b800000:# or start_pos >= 0x560000:
        if debug:
            print "*** Wine's memory chunk detected, ignored..."
            return

    if end_pos - start_pos > 1024 * 1024 * 50:
        if debug:
            print "*** Memory chunk bigger than 50 MB, ignored..."
            return

    if start_pos < 0x400000: # Junk
        if debug:
            print "*** Junk detected (stack memory), ignored segment at 0x%x" % start_pos
            return

    f_in.seek(start_pos)
    try:
        #print "Writting to ___file___ segment from 0x%x to 0x%x" % (start_pos, end_pos)
        f_out.write(f_in.read(end_pos - start_pos))
    except:
        pass
        #print "Error writting memory...", sys.exc_info()[1]


def dumpProcessMemory(pid, out_file, segments, debug=True):
    """ Dump every segment of the process """

    f_in = file("/proc/%d/mem" % pid, "rb")

    if type(out_file) == str:
        f_out = file(out_file, "wb")

    i = 0
    for segment in segments:
        i += 1
        if segment[0] > 0x7b800000:
            break
        elif segment[0] >= 0x400000:
            dumpSegment(f_in, f_out, segment, debug)

    if type(out_file) == str:
        f_out.close()

    f_in.close()


def cleanCmdLine(name):
    """ Extract filename and remove leading 0x00 chars """
    name = os.path.basename(name)
    name.strip("\x00")
    return name


def getProcessName(pid):
    """ Extract the program's name to dump """
    f = file("/proc/%d/cmdline" % pid, "r")
    tmp = f.read()
    #print "Process name without cleaning is %s" % tmp
    name = cleanCmdLine(f.read())
    #print "Clean process name is %s" % name
    f.close()

    return name


def getAddressFromLine(line):
    """ Extract the start_address and end_address from a line with the format of
        the file /proc/PID/smaps """
    chunk = line.split(" ")[0].split("-")
    start_address = int(chunk[0], 16)
    end_address = int(chunk[1], 16)

    return [start_address, end_address]


def advanceLines(f, lines):
    """ Advanced #<lines>  in file <f> """
    for i in xrange(lines): f.readline()


def getMemorySegments(pid, debug=True):
    """ Returns a list of [start_address, end_address] of the memory chunks """

    name = getProcessName(pid)
    name = extractFileName(name)

    debug = False
    if debug:
        print "*** Searching for process '%s'" % name

    maps = []

    f = file("/proc/%d/smaps" % pid, "r")
    process_found = False

    bDone = False
    while 1:
        line = f.readline()
        if not line:
            break

        if not bDone:
            line = line.strip("\n").strip("\r")
            #print line
            bDone = True

        if not process_found and line.find(name) == -1:
            continue
        elif not process_found and line.find(name) > -1:
            process_found = True
            address = getAddressFromLine(line)
            maps.append(address)
            advanceLines(f, 11) # Ignore the next 11 lines from /proc/PID/smaps
        elif process_found:
            fields = line.split(" ")

            if len(fields) > 6 and line.find(name) == -1: # Another process
                process_found = False
                continue

            address = getAddressFromLine(line)
            maps.append(address)
            advanceLines(f, 11) # Ignore the next 11 lines from /proc/PID/smaps

    f.close()

    return maps


class CPtraceDumper:
    """ Ptrace Dumper """

    # Output base file
    outFile = None
    # Pid of the process to dump
    pid = None

    # PtraceDebugger instance
    dbg = None
    # Process name
    processName = None

    def __init__(self, pid, outFile):
        """ Set the pid and the base output filename """
        self.pid = pid
        self.outFile = outFile

    def dump(self):
        """ Dump the memory """
        self.dbg = PtraceDebugger()
        #print "Created object"
        try:
            self.dbg.addProcess(self.pid, False)
            #print "Attached to process"
        except:
            #print "Error adding process", sys.exc_info()[1]
            pass
        try:
            #print "Resolving process's name"
            self.processName = getProcessName(self.pid)
            #print "Resolving segmnents"
            segments = getMemorySegments(self.pid, True)
            #print "SEGMENTS:", segments
            #print "Now dumping memory"
            dumpProcessMemory(self.pid, self.outFile, segments, True)
        except:
            pass
            #print "Exception in self.dump"
            #print sys.exc_info()[1]
            #raise

    def quit(self):
        """ Exit from ptrace debugger """
        #print "Quiting from ptrace debugger"
        self.dbg.quit()


def main(pid, out_file):
    """ Attach to the process, dump the memory and detach from it """
    dbg = CPtraceDumper(pid, out_file)
    dbg.dump()
    dbg.quit()


def usage():
    """ Show usage information """
    sys.stderr.writelines("Usage: " + sys.argv[0] + " <pid> <output file>")
    sys.stderr.write("\n")
    sys.stderr.flush()


if __name__ == "__main__":

    if len(sys.argv) != 3:
        usage()
    else:
        main(int(sys.argv[1]), sys.argv[2])

    sys.exit(0)
