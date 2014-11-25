from winappdbg import System,EventHandler
import random

class hook_handler(EventHandler):
    apiHooks = {
        # Hooks for the ws2_32 library.
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
        #print "post_recv is called"
        process = event.get_process()
        tid     = event.get_tid()
        params  = event.hook.get_params(tid)

        buf    = event.get_process().peek_string(params[1])
        buflen = len(buf)
        
        #print "Recv: ", buflen, buf
        # Replace meterpreter TLV format with random string
        # meterpreter will be neutralised and frozen
        if (buflen > 0):
            randomstr = '%x' % random.randrange(16**buflen)
            process.write(params[1],randomstr)
            
