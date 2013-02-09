################################################################
# Configuration options
#

# Dir
HOME_DIR = "/home/malware"
WINE_DIR = "%s/.wine" % (HOME_DIR)
WINE_BACKUP_DIR = "%s/.winebackup" % (HOME_DIR)
SAMPLE_DIR = "/tmp/vir"
EXEC_DIR = "%s/drive_c" % (WINE_DIR)

# X server
X_SERVER_NUMBER = "1"

# Path
CGI_PATH = "/cgi-bin"
KILL_XVFB_PATH = "%s/bin/kill_xvfb.sh %s" % (HOME_DIR, X_SERVER_NUMBER)
PREPARE_PATH = "%s/bin/prepare_zerowine.sh" % (HOME_DIR)
LAUNCHER_PATH = "xvfb-run -n %s %s/bin/malware_launcher.sh" % (X_SERVER_NUMBER, HOME_DIR)
DIFF_PATH = "%s/bin/diff_zerowine.sh" % (HOME_DIR)
PE_SIGNATURE_PATH = "%s/zerowine/userdb.txt" % (HOME_DIR)
UPX_PATH = "%s/bin/upx/upx" % (HOME_DIR)
TCPDUMP_PATH = "/usr/sbin/tcpdump"
PDFTK_PATH = "pdftk"
STRINGS_PATH = "strings"

# Non-GPL Path
NONGPL_DIR = "%s/nongpl" % (HOME_DIR)
TRID_PATH = "%s/bin/trid" % (NONGPL_DIR)
TRID_SIGNATURE_PATH = "%s/bin/TrIDDefs.TRD" % (NONGPL_DIR)

# Timeout
MIN_TIMEOUT = 10
MAX_TIMEOUT = 900

# File size
MIN_SIZE = 1024
MAX_SIZE = 104857600

# File name
CGI_DOWNLOAD_FILENAME = "download.py"
CGI_VIEW_FILENAME = "view.py"

FILE_NAME_ORIG_FILENAME = "file.name.orig.txt"
FILE_NAME_EXEC_FILENAME = "file.name.exec.txt"
FILE_HASH_FILENAME = "file.hash.txt"
FILE_HEADER_FILENAME = "file.header.txt"
FILE_STRING_FILENAME = "file.string.txt"
FILE_PDF_ANALYSIS_FILENAME = "file.pdf.analysis.txt"
FILE_PDF_JAVASCRIPT_ORIG_FILENAME = "file.pdf.javascript.orig.txt"
FILE_SIZE_FILENAME = "file.size.txt"

REPORT_FILENAME = "report.txt"
REPORT_SIGNATURE_FILENAME = "report.signature.txt"
REPORT_WARNING_FILENAME = "report.warning.txt"

DIFF_FILENAME = "diff.txt"

TRICK_DEBUG_FILENAME = "trick.debug.txt"
TRICK_VM_FILENAME = "trick.vm.txt"

ANALYZE_START_FILENAME = "analyze.start.txt"
ANALYZE_FINISH_FILENAME = "analyze.finish.txt"

TCPDUMP_FILENAME = "dump-network-pcap"

TAGS_FILENAME = "tags.txt"

# Other
TCPDUMP_OPTION_READ = "-vvv -x -X"
STRINGS_OPTION = "-n 4" # Do not change this. If you change this, libmalware.py's getPdfJavaScript function will be broken.

ALLOW_MULTIPLE_USERS = False
DEFAULT_UMASK = 022

# Display debug output
DEBUG = True

# Buffer
USE_BUFFER = True # If you want full analysis: Please disable this.
                  # Else if you want quick analysis: Please enable this.
BUFFER_SIZE = 2097152

#
################################################################
