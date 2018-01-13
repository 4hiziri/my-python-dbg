from ctypes import *
from mydbgclasses import *

kernel32 = windll.kernel32


class Debugger:
    def __init__(self):
        self.h_process = None
        self.debugger_active = False
        self.pid = int(-1)

    def load(self, debuggee_path):
        creation_flags = DEBUG_PROCESS

        startup_info = STARTUPINFO()
        process_info = PROCESS_INFORMATION()

        startup_info.dwFlags = 0x1
        startup_info.wShowWindow = 0x0

        startup_info.cb = sizeof(startup_info)

        if kernel32.CreateProcessA(debuggee_path,
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
            self.h_process = self.open_process(process_info.dwProcessId)
        else:
            print("error: {}".format(kernel32.GetLastError()))

    def open_process(self, pid):
        return kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

    def attach(self, pid):
        self.h_process = self.open_process(pid)

        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
        else:
            print("unable to attach")

    def run(self):
        while self.debugger_active:
            self.get_debug_event()

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            input("press any key to continue...")
            self.debugger_active = False
            kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                        debug_event.dwThreadId,
                                        continue_status)

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print("Finish debugging")
            return True
        else:
            print("Detach Error")
            return False
