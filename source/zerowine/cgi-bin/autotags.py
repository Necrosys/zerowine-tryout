autoTags = [
	# Automatic tagging
	# {'dataType':'blah', 'method':'blah', 'target':'blah', 'result':'blah'}

	# Start
	{'dataType':'diff', 'method':'start', 'target':'+"PendingFileRenameOperations"=', 'result':'PendingFileRenameOperations'},

	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Active Setup\\\\Installed Components\\\\', 'result':'Active Setup'},

	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Internet Explorer\\\\', 'result':'Change Internet Explorer settings'},

	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\', 'result':'Image File Execution Options'},
	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows] ', 'result':'Automatic startup'},

	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced] ', 'result':'Change Explorer settings'},
	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Browser Helper Objects\\\\', 'result':'BHO'},
	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings', 'result':'Change internet settings'},
	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run', 'result':'Automatic startup'},
	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run', 'result':'Automatic startup'},

	{'dataType':'diff', 'method':'start', 'target':'+[System\\\\CurrentControlSet\\\\Services\\\\', 'result':'Service creation'},

	{'dataType':'diff', 'method':'start', 'target':'c:/windows/system32/drivers/etc/hosts', 'result':'hosts file modification'},
	
	{'dataType':'diff', 'method':'start', 'target':'+shell=', 'result':'Automatic startup'},

	# Substring
	{'dataType':'diff', 'method':'substring', 'target':'\\\\shell\\\\open\\\\command] ', 'result':'shell open command'},

	# End
	{'dataType':'diff', 'method':'end', 'target':'.exe differ\n', 'result':'EXE file modification'},
	{'dataType':'diff', 'method':'end', 'target':'.dll differ\n', 'result':'DLL file modification'},
	# False positive (c:/users/USERNAME/Local Settings/Temporary Internet Files/Content.IE5/index.dat)
#	{'dataType':'diff', 'method':'end', 'target':' differ\n', 'result':'File modification'},
	{'dataType':'diff', 'method':'end', 'target':'/autorun.inf\n', 'result':'Autorun'}
]
