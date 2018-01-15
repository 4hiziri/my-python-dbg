from ctypes import *
import time

msvcrt = cdll.msvcrt
counter = 0

while True:
    # msvcrt.printf("loop iteration {}".format(counter).encode('UTF-8'))
    msvcrt.printf(b"test %d\n", counter)
    time.sleep(2)
    counter += 1
