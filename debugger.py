#! /usr/bin/python3
'''
Main Debugger module
'''

from ctypes import sizeof, byref, windll
from debugger_defines import (
    PROCESS_INFORMATION,
    STARTUP_INFO,
    #DEBUG_PROCESS,
    CREATE_NEW_CONSOLE,
    PROCESS_ALL_ACCESS,
    DEBUG_EVENT,
    DBG_CONTINUE,
    INFINITE
)

KERNEL32 = windll.kernel32

class Debugger():
    '''
    Debugger instance
    '''
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False

    def load(self, path_to_exe):
        '''
        Loads a new process
        '''
        #dwCreation flag determines how to create the process
        #set to CREATE_NEW_CONSOLE to see GUI
        creation_flags = CREATE_NEW_CONSOLE #DEBUG_PROCESS

        #required structs for process creation
        startupinfo = STARTUP_INFO()
        process_information = PROCESS_INFORMATION()

        #allow the process to be shown in a separate window
        startupinfo.wFlags = 0x1
        startupinfo.wShowWindow = 0x0

        #set the size of the struct
        startupinfo.cb = sizeof(startupinfo)

        if KERNEL32.CreateProcessW(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):
            print("[*] Process launched")
            print("[*] PID: %d" % process_information.dwProcessId)
            #get a handle to the created process
            self.h_process = self.open_process(process_information.dwProcessId)
        else:
            print("[*] Error: 0x%08x." % KERNEL32.GetLastError())

    def open_process(self, pid):
        '''
        Open a running process with PROCESS_ALL_ACCESS flag
        '''
        return KERNEL32.OpenProcess(PROCESS_ALL_ACCESS,
                                    pid,
                                    False)

    def attach(self, pid):
        '''
        Attach debugger instance to a running process
        '''
        self.h_process = self.open_process(pid)
        pid = int(pid)
        if KERNEL32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = pid
            self.run()
        else:
            print("[*] Unable to attach to process " + str(pid))

    def run(self):
        '''
        Starts polling the debuggee process for debugging events
        '''
        while self.debugger_active:
            self.get_debug_event()

    def get_debug_event(self):
        '''
        Get and handle debug event
        '''
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if KERNEL32.WaitForDebugEvent(byref(debug_event), INFINITE):
            #TODO: event handlers
            input("Press a key to continue...")
            self.debugger_active = False
            KERNEL32.ContinueDebugEvent(debug_event.dwProcessId,
                                        debug_event.dwThreadId,
                                        continue_status)

    def detach(self):
        '''
        Detach debugger instance from the debuggee process
        '''
        if KERNEL32.DebugActiveProcessStop(self.pid):
            print("[*] Debugging session ended. Exiting...")
            return True
        else:
            print("Error trying to detach from process " + str(self.pid))
            return False
