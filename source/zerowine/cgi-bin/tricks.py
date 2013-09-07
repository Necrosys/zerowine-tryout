DETECTION_TRICKS = {
    # Virtual Machine detection trick(s)
    # Static detection only!

    "Red Pill": "\x0f\x01\x0d\x00\x00\x00\x00\xc3",
    "VMCheck.dll": "\x45\xC7\x00\x01",
    "Torpig VMM trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
    "Torpig (UPX) VMM trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3",

    # Hyper-V detection trick(s)
    "Hyper-V (1)": "VirtualMachine",
    "Hyper-V (2)": "vmicheartbeat",
    "Hyper-V (3)": "vmicvss",
    "Hyper-V (4)": "vmicshutdown",
    "Hyper-V (5)": "vmicexchange",
    # Too general :(
    #	"Hyper-V (6)":"Hyper-V",

    # VMware detection trick(s)
    "VMware (Special port)": "VMXh",
    "VMware (Special port, Reversed string)": "hXMV",

    "VMware (Replay Debugging Driver)": "vmdebug",
    "VMware (Pointing Device Driver)": "vmmouse",
    "VMware (Tools Service)": "VMTools",
    "VMware (Server Memory Controller Service)": "VMMEMCTL",
    # Too general :(
    #	"VMware":"vmware",

    ## Process(es)
    "VMware (Tools Service)": "vmwareuser.exe",
    "VMware (Tools tray application)": "vmwaretray.exe",

    # Virtual PC detection trick(s)
    "Virtual PC (Special instruction)": "\x0F\xC7\xC8",
    "Virtual PC (Special instruction)": "\x0f\x3f\x07\x0b",
    "VMCheck.dll for Virtual PC (Special instruction)": "\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",

    "Virtual PC (Host Bus Driver)": "vpcbus",
    "Virtual PC (Virtual Machine S3 Miniport Driver)": "vpc-s3",
    "Virtual PC (Virtual USB Hub Driver)": "vpcuhub",
    "Virtual PC (Mouse Integration Filter Driver)": "msvmmouf",

    ## Process(es)
    "Virtual PC (Virtual Machine Services)": "vmsrvc.exe",
    "Virtual PC (Virtual Machine User Services)": "vmusrvc.exe",

    # VirtualBox detection trick(s)
    "VirtualBox (ACPI)": "VBOX__",
    "VirtualBox (Mouse)": "VBoxMouse",
    "VirtualBox (Guest Additions)": "VBoxGuest",
    "VirtualBox (Service)": "VBoxService",
    "VirtualBox (Shared Folders)": "VBoxSF",
    # Too short :(
    #	"VirtualBox (SystemBiosVersion)":"VBOX",

    ## Process(es)
    "VirtualBox (Guest Additions Service)": "vboxservice.exe",
    "VirtualBox (Guest Additions Tray Application)": "vboxtray.exe",

    # Xen hypervisor detection trick(s)
    "Xen (CPUID)": "XenVMM", # Or XenVMMXenVMM
    "Xen (XenPCI Driver)": "xenevtchn",
    "Xen (XenNet Driver)": "xennet",
    "Xen (XenNet Driver)": "xennet6",
    "Xen (Citrix Tools for Virtual Machines Service)": "xensvc",
    "Xen (Typo?)": "xenvdb",
    "Xen (XenVbd Driver)": "xenvbd",

    ## Process(es)
    "Xen (XenSource Windows guest agent)": "xenservice.exe",

    # Bochs & QEMU detection trick(s)
    "Bochs & QEMU (CPUID)": "\x44\x4d\x41\x63"
}

DEBUGGING_TRICKS = {
    # Debugger detection trick(s)
    # Dynamic detection only!

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

    "SICE": "SoftIce detection",
    "SIWVID": "SoftIce detection",
    "NTICE": "SoftIce detection",
    "REGSYS": "Regmon detection",
    "REGVXG": "Regmon detection",
    "FILEVXG": "Filemon detection",
    # False positives (CreateFileMapping, IsBadStringPtrW)
    #	"FILEM":"Filemon detection",
    #	"TRW":"TRW detection",
    "TWX": "TRW detection",
    "ICEEXT": "SoftIce detection",
    "NTFIRE.S": "'DemoVDD By elicz' technique",

    "OLLYDBG": "OllyDbg detection",
    "FileMonClass": "Filemon detection",
    "RegMonClass": "Regmon detection",
    "isDebuggerPresent": "Generic debugger detection",
    "CheckRemoteDebuggerPresent": "Generic debugger detection",
    "OutputDebugString": "Generic debugger detection",
    "SoftICE": "SoftIce detection",
    "Compuware": "SoftIce detection",
    "NuMega": "SoftIce detection",
    "WinDbgFrameClass": "WinDbg detection",
    "GBDYLLO": "Themida's trick",
    "pediy0": "Themida's trick",
    "PROCMON_WINDOW_CLASS": "Procmon detection",
    "cws_": "CWSandbox detection",
    "cwmonitor": "CWSandbox detection",
    "SmartSniff": "SmartSniff detection",
    "PacketSnifferClass1": "Unknown packet sniffer detection",
    "wireshark.exe": "Wireshark detection",
    "The Ethereal Network Analyzer": "Ethereal detection",
    "SysAnalyzer": "SysAnalyzer detection",
    "api_log.dll": "SysAnalyzer detection",
    "dir_watch.dll": "SysAnalyzer detection",
    "sniff_hit": "SysAnalyzer detection",
    "InsideTm": "Anubis detection",
    "joeboxserver.exe": "Joebox detection",
    "joeboxcontrol.exe": "Joebox detection",
    "VBoxService.exe": "VirtualBox detection",
    "SbieDll.dll": "Sandboxie detection",
    #	"dbghelp.dll":"Debug help library detection",
    "LOG_API.DLL": "Buster Sandbox Analyzer detection",
    "WPE PRO": "Winsock Packet Editor Pro detection",
    "MiniSniffer": "MiniSniffer detection",
    "EtherDetect Packet Sniffer": "EtherDetect Packet Sniffer detection",
    "Uhack - ": "Uhack detection",
    "Winsock Expert": "Winsock Expert detection",
    "Windows File Protection": "Windows File Protection detection",
    "18467-41": "Generic Sysinternals tool detection",
    "Syser": "Syser Debugger detection",
    "SyserDbgMsg": "Syser Debugger detection",
    "SyserBoot": "Syser Debugger detection",
    "AVP.AlertDialog": "Kaspersky Anti Virus detection",
    "AVP.Product_Notification": "Kaspersky Anti Virus detection",
    "AHNTASK_SESSION": "AhnLab Anti Virus detection",
    "wscui_class": "Windows Security Center detection",
    "wine_get_unix_file_name": "Possible Wine detection",
    "wine_get_dos_file_name": "Possible Wine detection"
}
