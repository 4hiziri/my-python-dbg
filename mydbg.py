from ctypes import *
from mydbgclasses import *

kernel32 = windll.kernel32


class Debugger:
    def __init__(self):
        pass

    def load(self, debugee_path):
        creation_flags = DEBUG_PROCESS

        startup_info = STARTUPINFO()
        process_info = PROCESS_INFOMATION()

        startup_info.dwFlags = 0x1
        startup_info.wShowWindow = 0x0

        startup_info.cb = sizeof(startup_info)

        if kernel32.CreateProcessA(debugee_path,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startup_info),
                                   byref(process_info)):
            print("launch process")
            print("pid: {}".format(process_info.dwProcessId))
        else:
            print("error: {}".format(kernel32.GetLastError()))
