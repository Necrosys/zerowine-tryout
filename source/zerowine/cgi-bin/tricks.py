DETECTION_TRICKS = {
	"Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
	"Virtual PC trick":"\x0f\x3f\x07\x0b",
	"VMware trick":"VMXh",
	"VMCheck.dll":"\x45\xC7\x00\x01",
	"VMCheck.dll for Virtual PC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
	"Virtual PC trick":"\x0F\xC7\xC8",
	"Xen":"XenVMM", # Or XenVMMXenVMM
	"Bochs & QEmu CPUID trick":"\x44\x4d\x41\x63",
	"Torpig VMM trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
	"Torpig (UPX) VMM trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
	}

DEBUGGING_TRICKS = {
	"""
	
	Should be this way but, well, Python is a shit to analyze an string with the char '\'.
	
	"%%.%SICE":"SoftIce detection",
	"%%.%SIWVID":"SoftIce detection",
	"%%.%NTICE":"SoftIce detection",
	"%%.%REGSYS":"Regmon detection",
	"%%.%REGVXG":"Regmon detection",
	"%%.%FILEVXG":"Filemon detection",
	"%%.%FILEM":"Filemon detection",
	"%%.%TRW":"TRW detection",
	"%%.%TWX":"TRW detection",
	"%%.%ICEEXT":"SoftIce detection",
	"%%.%NTFIRE.S":"'DemoVDD By elicz' technique",
	"""
	
	"SICE":"SoftIce detection",
	"SIWVID":"SoftIce detection",
	"NTICE":"SoftIce detection",
	"REGSYS":"Regmon detection",
	"REGVXG":"Regmon detection",
	"FILEVXG":"Filemon detection",
	# False positives (CreateFileMapping, IsBadStringPtrW)
#	"FILEM":"Filemon detection",
#	"TRW":"TRW detection",
	"TWX":"TRW detection",
	"ICEEXT":"SoftIce detection",
	"NTFIRE.S":"'DemoVDD By elicz' technique",
	
	"OLLYDBG":"OllyDbg detection",
	"FileMonClass":"Filemon detection",
	"RegMonClass":"Regmon detection",
	"isDebuggerPresent":"Generic debugger detection",
	"CheckRemoteDebuggerPresent":"Generic debugger detection",
	"OutputDebugString":"Generic debugger detection",
	"SoftICE":"SoftIce detection",
	"Compuware":"SoftIce detection",
	"NuMega":"SoftIce detection",
	"WinDbgFrameClass":"WinDbg detection",
	"GBDYLLO": "Themida's trick",
	"pediy0":"Themida's trick",
	"PROCMON_WINDOW_CLASS":"Procmon detection",
	"cws_":"CWSandbox detection",
	"cwmonitor":"CWSandbox detection",
	"SmartSniff":"SmartSniff detection",
	"PacketSnifferClass1":"Unknown packet sniffer detection",
	"wireshark.exe":"Wireshark detection",
	"The Ethereal Network Analyzer":"Ethereal detection",
	"SysAnalyzer":"SysAnalyzer detection",
	"api_log.dll":"SysAnalyzer detection",
	"dir_watch.dll":"SysAnalyzer detection",
	"sniff_hit":"SysAnalyzer detection",
	"InsideTm":"Anubis detection",
	"joeboxserver.exe":"Joebox detection",
	"joeboxcontrol.exe":"Joebox detection",
	"VBoxService.exe":"VirtualBox detection",
	"SbieDll.dll":"Sandboxie detection",
#	"dbghelp.dll":"Debug help library detection",
	"LOG_API.DLL":"Buster Sandbox Analyzer detection",
	}
