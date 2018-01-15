from ctypes import *
from mydbgclasses import *

kernel32 = windll.kernel32


class Debugger:
    def __init__(self):
        self.h_process = None
        self.h_thread = None
        self.context = None
        self.debugger_active = False
        self.pid = int(-1)
        self.exception_address = None
        self.software_breakpoints = {}

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
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(h_thread=self.h_thread)

            print("Event Code = {}, Thread ID = {}".format(debug_event.dwDebugEventCode, debug_event.dwThreadId))

            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if exception == EXCEPTION_ACCESS_VIOLATION:
                    print("Access Violation Detected")
                elif exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif exception == EXCEPTION_GUARD_PAGE:
                    print("Guard Page Access Detected")
                elif exception == EXCEPTION_SINGLE_STEP:
                    print("Signal stepping")

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

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if h_thread is not 0:
            return h_thread
        else:
            print("OpenThread Error")
            return None

    def enumerate_threads(self):
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot is None:
            return None

        thread_entry = THREADENTRY32()
        thread_entry.dwSize = sizeof(thread_entry)
        thread_list = []

        if kernel32.Thread32First(snapshot, byref(thread_entry)):
            if thread_entry.th32OwnerProcessID == self.pid:
                thread_list.append(thread_entry.th32ThreadID)

            while kernel32.Thread32Next(snapshot, byref(thread_entry)):
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)

        kernel32.CloseHandle(snapshot)
        return thread_list

    def get_thread_context(self, thread_id=None, h_thread=None):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        if h_thread is None:
            h_thread = self.open_thread(thread_id)

        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            return None

    def exception_handler_breakpoint(self):
        print("Inside breakpoint handler")
        print("Exception addr: 0x{:X}".format(self.exception_address))
        return DBG_CONTINUE

    def read_process_memory(self, address, length):
        read_buf = create_string_buffer(length)
        count = c_ulong(0)

        if kernel32.ReadProcessMemory(self.h_process,
                                      address,
                                      read_buf,
                                      length,
                                      byref(count)):
            return read_buf.raw
        else:
            return False

    def write_process_memory(self, address, data):
        count = c_ulong(0)
        length = len(data)

        c_data = c_char_p(data[count.value:])

        if kernel32.WriteProcessMemory(self.h_process,
                                       address,
                                       c_data,
                                       length,
                                       byref(count)):
            return True
        else:
            return False

    def bp_set_sw(self, address):
        print("Set breakpoint at: 0x{:X}".format(address))
        if address not in self.software_breakpoints:
            try:
                original_byte = self.read_process_memory(address, 1)
                self.write_process_memory(address, "\xCC")
                self.software_breakpoints[address] = (original_byte)
            except Exception as e:
                print(e)
                return False

    def func_resolve(self, dll, func):
        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, func)
        kernel32.CloseHandle(handle)
        return address
