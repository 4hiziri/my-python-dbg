from ctypes import *

WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p

DEBUG_PROCESS = 0x1
CREATE_NEW_CONSOLE = 0x10

# standard access rights
DELETE = 0x10000
READ_CONTROL = 0x20000
WRITE_DAC = 0x40000
WRITE_OWNER = 0x80000
SYNCHRONIZE = 0x100000

# process access rights
PROCESS_TERMINATE = 0x0001  # TerminateProcess
PROCESS_CREATE_THREAD = 0x0002  # permit create thread
PROCESS_VM_OPERATION = 0x0008  # VirtualProtectEx WriteProcessMemory
PROCESS_VM_READ = 0x0010  # ReadProcessMemory
PROCESS_VM_WRITE = 0x0020  # WriteProcessMemory
PROCESS_DUP_HANDLE = 0x0040  # DuplicateHandle
PROCESS_CREATE_PROCESS = 0x0080  # permit create process
PROCESS_SET_QUOTA = 0x0100  # SetProcessWorkingSetSize
PROCESS_SET_INFORMATION = 0x0200  # SetPriorityClass
PROCESS_QUERY_INFORMATION = 0x400  # OpenProcessToken
PROCESS_SUSPEND_RESUME = 0x0800  # permit resume process
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000  # GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName
PROCESS_ALL_ACCESS = PROCESS_TERMINATE | \
                     PROCESS_CREATE_THREAD | \
                     PROCESS_VM_OPERATION | \
                     PROCESS_VM_READ | \
                     PROCESS_VM_WRITE | \
                     PROCESS_DUP_HANDLE | \
                     PROCESS_CREATE_PROCESS | \
                     PROCESS_SET_QUOTA | \
                     PROCESS_SET_INFORMATION | \
                     PROCESS_QUERY_INFORMATION | \
                     PROCESS_SUSPEND_RESUME | \
                     PROCESS_QUERY_LIMITED_INFORMATION


class STARTUPINFO(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPTSTR),
        ("lpDesktop", LPTSTR),
        ("lpTitle", LPTSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


class PROCESS_INFOMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]