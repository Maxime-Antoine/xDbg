#! /usr/bin/python3
'''
Main Debugger module
Works only on Windows x64
'''

from ctypes import (
    sizeof,
    byref,
    windll
)

from debugger_defines import (
    #DEBUG_PROCESS,
    CREATE_NEW_CONSOLE,
    STARTUP_INFO,
    PROCESS_INFORMATION,
    PROCESS_ALL_ACCESS,
    DEBUG_EVENT,
    DBG_CONTINUE,
    INFINITE,
    THREAD_ALL_ACCESS,
    THREAD_ENTRY32,
    TH32CS_SNAPTHREAD,
    CONTEXT32,
    CONTEXT64,
    CONTEXT_FULL,
    CONTEXT_DEBUG_REGISTERS,
    DWORD
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
        self.debuggee_is_wow64 = None

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
            self._check_process_type(self.h_process)
        else:
            print("[*] Error: 0x%08x." % KERNEL32.GetLastError())

    def open_process(self, pid):
        '''
        Open a running process with PROCESS_ALL_ACCESS flag
        '''
        h_process = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS,
                                         False,
                                         pid)
        if h_process is not None:
            self._check_process_type(h_process)
            return h_process
        else:
            print('[Err]: 0x%08x ' % KERNEL32.GetLastError() + ' while trying to open process '
                  + str(pid))
            return False

    def attach(self, pid):
        '''
        Attach debugger instance to a running process
        '''
        pid = int(pid)
        self.h_process = self.open_process(pid)
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
            #put event handlers here
            self.debugger_active = False
            KERNEL32.ContinueDebugEvent(debug_event.dwProcessId,
                                        debug_event.dwThreadId,
                                        continue_status)

    def detach(self):
        '''
        Detach debugger instance from the debuggee process or False
        '''
        if KERNEL32.DebugActiveProcessStop(self.pid):
            print("[*] Debugging session ended. Exiting...")
            return True
        else:
            print("Error trying to detach from process " + str(self.pid))
            return False

    def open_thread(self, thread_id):
        '''
        Return a handle to the thread having the given TID or False
        '''
        h_thread = KERNEL32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if h_thread is not None:
            return h_thread
        else:
            print("[*] Could not obtain a valid thread handle")
            return False

    def enumerate_threads(self):
        '''
        Enumerate system threads to retrieve the TID of the ones belonging to debugee process
        If fails, return False
        '''
        thread_entry = THREAD_ENTRY32()
        thread_list = []
        snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot is not None:
            #Mandatory to set the size of the struct
            thread_entry.dwSize = sizeof(thread_entry)
            success = KERNEL32.Thread32First(snapshot, byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessId == self.pid:
                    thread_list.append(thread_entry.th32ThreadId)

                success = KERNEL32.Thread32Next(snapshot, byref(thread_entry))

            KERNEL32.CloseHandle(snapshot)
            return thread_list
        else:
            return False

    def get_thread_context(self, thread_id):
        '''
        Returns the context of the thread having the given TID or False
        '''
        #Obtain a handle to the thread
        h_thread = self.open_thread(thread_id)
        if h_thread:
            if self.debuggee_is_wow64:
                context = CONTEXT32()
                context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
                KERNEL32.Wow64GetThreadContext(h_thread, byref(context))
            else:
                context = CONTEXT64()
                context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
                KERNEL32.GetThreadContext(h_thread, byref(context))
            KERNEL32.CloseHandle(h_thread)
            return context
        else:
            return False

    def _check_process_type(self, h_process):
        '''
        Check if process is WoW64 or native x64
        '''
        process_is_wow64 = DWORD()
        KERNEL32.IsWow64Process(h_process, byref(process_is_wow64))
        if process_is_wow64.value:
            self.debuggee_is_wow64 = True
            print("[*] Process is WoW64")
        else:
            self.debuggee_is_wow64 = False
            print("[*] Process is x64")
