import mydbg
from mydbgclasses import HW_EXECUTE

dbg = mydbg.Debugger()
# dbg.load(b"C:\\Windows\\System32\\calc.exe")

pid = input("Enter PID: ")

dbg.attach(int(pid))
printf_addr = dbg.func_resolve(b"msvcrt.dll", b"printf")
print(printf_addr)
print("printf addr: {:X}".format(printf_addr))
dbg.bp_set_sw(printf_addr)
dbg.bp_set_hw(printf_addr, 1, HW_EXECUTE)

threads = dbg.enumerate_threads()

for thread in threads:
    thread_context = dbg.get_thread_context(thread)
    print('-----------------------------------')
    print("TID: {}".format(thread))
    print("RIP: {}".format(thread_context.Rip))
    print("RSP: {}".format(thread_context.Rsp))
    print("RBP: {}".format(thread_context.Rbp))
    print("RAX: {}".format(thread_context.Rax))
    print("RBX: {}".format(thread_context.Rbx))
    print("RCX: {}".format(thread_context.Rcx))
    print("RDX: {}".format(thread_context.Rdx))
    print('-----------------------------------')

dbg.run()
dbg.detach()
