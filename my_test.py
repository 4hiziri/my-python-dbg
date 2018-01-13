import mydbg

dbg = mydbg.Debugger()
# dbg.load(b"C:\\Windows\\System32\\calc.exe")

pid = input("Enter PID: ")

dbg.attach(int(pid))
dbg.run()
dbg.detach()
