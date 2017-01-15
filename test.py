#! /usr/bin/python3
'''
Simple test scratchpad
'''
#Disable constant name convention checks
#pylint: disable=C0103

# from ctypes import *

# msvcrt = cdll.msvcrt
# msg = "Hello World!\n"
# msvcrt.wprintf("Testing: %s", msg)

import debugger

debugger = debugger.Debugger()
#DEBUGGER.load(r"C:\Windows\system32\calc.exe")
pid = 8976 #input("Enter the PID fo the process to attach to: ")
debugger.attach(pid)

threads = debugger.enumerate_threads()
print("[*] " + str(len(threads)) + " threads in process " + str(pid))

#pylint assess incorrectly thread_context type
#pylint: disable=E1101

#Output registers value for each thread owned by the process
for thread in threads:
    thread_context = debugger.get_thread_context(thread)
    print("[*] Dumping registers for thread ID: " + str(thread))
    if thread_context and debugger.debuggee_is_wow64:
        print("[**] EIP: 0x%08x" % thread_context.Eip)
        print("[**] ESP: 0x%08x" % thread_context.Esp)
        print("[**] EBP: 0x%08x" % thread_context.Ebp)
        print("[**] EAX: 0x%08x" % thread_context.Eax)
        print("[**] EBX: 0x%08x" % thread_context.Ebx)
        print("[**] ECX: 0x%08x" % thread_context.Ecx)
        print("[**] EDX: 0x%08x" % thread_context.Edx)
    elif thread_context and not debugger.debuggee_is_wow64:
        print("[**] RAX: 0x%08x" % thread_context.Rax)
        print("[**] RCX: 0x%08x" % thread_context.Rcx)
        print("[**] RDX: 0x%08x" % thread_context.Rdx)
        print("[**] RBX: 0x%08x" % thread_context.Rbx)
        print("[**] RSP: 0x%08x" % thread_context.Rbp)
        print("[**] RBP: 0x%08x" % thread_context.Rbp)
        print("[**] RSI: 0x%08x" % thread_context.Rsi)
        print("[**] RDI: 0x%08x" % thread_context.Rdi)
        print("[**] R8: 0x%08x" % thread_context.R8)
        print("[**] R9: 0x%08x" % thread_context.R9)
        print("[**] R10: 0x%08x" % thread_context.R10)
        print("[**] R11: 0x%08x" % thread_context.R11)
        print("[**] R12: 0x%08x" % thread_context.R12)
        print("[**] R13: 0x%08x" % thread_context.R13)
        print("[**] R14: 0x%08x" % thread_context.R14)
        print("[**] R15: 0x%08x" % thread_context.R15)
        print("[**] Rip: 0x%08x" % thread_context.Rip)
    else:
        print("Cannot retrieve context for thread " + str(thread))
debugger.detach()
