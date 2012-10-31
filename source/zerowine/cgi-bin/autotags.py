autoTags = [
	# Automatic tagging
	# {'dataType':'blah', 'method':'blah', 'target':'blah', 'result':'blah'}
	{'dataType':'diff', 'method':'start', 'target':'+[System\\\\CurrentControlSet\\\\Services\\\\', 'result':'Service creation'},
	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run', 'result':'Automatic startup'},
	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings', 'result':'Change internet settings'},
	{'dataType':'diff', 'method':'start', 'target':'+[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Browser Helper Objects\\\\', 'result':'BHO'},
	{'dataType':'diff', 'method':'start', 'target':'+"PendingFileRenameOperations"=', 'result':'PendingFileRenameOperations'},
	{'dataType':'diff', 'method':'end', 'target':' differ\n', 'result':'File modification'}
]
