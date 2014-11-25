from winappdbg import System,EventHandler

class hook_handler(EventHandler):
    apiHooks = {
        # Hooks for the kernel32 library.
        'ws2_32.dll' : [
            ( 'recv',4),
        ],        
    }
    #int recv(
    #_In_   SOCKET s,
    #_Out_  char *buf,
    #_In_   int len,
    #_In_   int flags
    #);    
    def post_recv(self, event, retval):
        process = event.get_process()
        tid     = event.get_tid()
        params  = event.hook.get_params(tid)

        buf    = event.get_process().peek_string(params[1])
        buflen = len(buf)
        
        #print "Recv: ", buflen, buf
        # Replace meterpreter TLV format with terminate \0 string
        # meterpreter will be neutralised and frozen
        if (buflen > 0):
            process.write(params[1],"\0")
            #buf = event.get_process().peek_string(params[1])
            #print "--> changed: ", buflen, buf
