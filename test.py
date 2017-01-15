#! /usr/bin/python3
'''
Simple test scratchpad
'''

# from ctypes import *

# msvcrt = cdll.msvcrt
# msg = "Hello World!\n"
# msvcrt.wprintf("Testing: %s", msg)

import debugger

DEBUGGER = debugger.Debugger()
#DEBUGGER.load(r"C:\Windows\system32\calc.exe")
PID = input("Enter the PID fo the process to attach to: ")
DEBUGGER.attach(PID)
DEBUGGER.detach()
