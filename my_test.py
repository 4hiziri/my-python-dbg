import mydbg

dbg = mydbg.Debugger()
# dbg.load(b"C:\\Windows\\System32\\calc.exe")

pid = input("Enter PID: ")

dbg.attach(int(pid))
threads = dbg.enumerate_threads()

for thread in threads:
    thread_context = dbg.get_thread_context(thread)
    print('-----------------------------------')
    print("TID: {}".format(thread))
    print("EIP: {}".format(thread_context.Eip))
    print("ESP: {}".format(thread_context.Esp))
    print("EBP: {}".format(thread_context.Ebp))
    print("EAX: {}".format(thread_context.Eax))
    print("EBX: {}".format(thread_context.Ebx))
    print("ECX: {}".format(thread_context.Ecx))
    print("EDX: {}".format(thread_context.Edx))
    print('-----------------------------------')

dbg.run()
dbg.detach()
