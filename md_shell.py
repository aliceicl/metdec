from winappdbg import Process,EventHandler
import mdlog

class hook_handler(EventHandler):
    apiHooks = {
        # Hooks for the kernel32 library.
        'kernel32.dll' : [
            #  Function Parameters
            ( 'CreateProcessW' , 10 ),
            ( 'CreateProcessA' , 10 ),          
            ]
        }
        
    def pre_CreateProcessW(self, event, ra, lpApplicationName, lpCommandLine, lpProcessAttributes,
                       lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,
                       lpCurrentDirectory,lpStartupInfo,lpProcessInformation
                       ):
        #print "pre_CreateProcessW is called\n"
        process = event.get_process()
        try:
            appname = process.peek_string(lpApplicationName, fUnicode=True)
            cmdline = process.peek_string(lpCommandLine, fUnicode=True)
            cmdlist = [appname,cmdline]
            #print cmdlist
            mdlog.print_console(mdlog.INFO_LEVEL,("[*] CreateProcessW is called with ** " + str(cmdlist)))
            

            # insert the missing \0 bytes to write unicode properly
            # recommended by Mario Vilas
            if (appname.lower().find("ipconfig")>=0):
                if (cmdline.lower().find("all")>=0):
                    changedappname = "C\0:\0\\\0m\0e\0t\0d\0e\0c\0\\\0m\0d\0_\0i\0p\0c\0o\0n\0f\0i\0g\0_\0a\0l\0l\0.\0e\0x\0e\0\0\0"
                else:
                    changedappname = "C\0:\0\\\0m\0e\0t\0d\0e\0c\0\\\0m\0d\0_\0i\0p\0c\0o\0n\0f\0i\0g\0.\0e\0x\0e\0\0\0"
            elif (appname.lower().find("tasklist")>=0):
                changedappname = "C\0:\0\\\0m\0e\0t\0d\0e\0c\0\\\0m\0d\0_\0t\0a\0s\0k\0l\0i\0s\0t\0.\0e\0x\0e\0\0\0"
            elif (appname.lower().find("netstat")>=0):
                changedappname = "C\0:\0\\\0m\0e\0t\0d\0e\0c\0\\\0m\0d\0_\0n\0e\0t\0s\0t\0a\0t\0.\0e\0x\0e\0\0\0"
            elif (appname.lower().find("hostname")>=0):
                changedappname = "C\0:\0\\\0m\0e\0t\0d\0e\0c\0\\\0m\0d\0_\0h\0o\0s\0t\0n\0a\0m\0e\0.\0e\0x\0e\0\0\0"
            elif (appname.lower().find("whoami")>=0):
                changedappname = "C\0:\0\\\0m\0e\0t\0d\0e\0c\0\\\0m\0d\0_\0w\0h\0o\0a\0m\0i\0.\0e\0x\0e\0\0\0"
            elif (appname.lower().find("net")>=0 and cmdline.lower().find("user")):
                changedappname = "C\0:\0\\\0m\0e\0t\0d\0e\0c\0\\\0m\0d\0_\0n\0e\0t\0_\0u\0s\0e\0r\0.\0e\0x\0e\0\0\0"
            else:   
                changedappname = "C\0:\0\\\0m\0e\0t\0d\0e\0c\0\\\0g\0a\0r\0b\0a\0g\0e\0.\0e\0x\0e\0\0\0"
            #print "Change:" + changedappname
            process.write(lpApplicationName,changedappname)
            #process.write(lpCommandLine,changedcmdline)
    
        except Exception, e:
            mdlog.print_console(mdlog.ERROR_LEVEL,("[-] Error in hooking " + str(e)))
            process.kill()
            
            

            
