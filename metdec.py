from winappdbg import System,Process,Debug, EventHandler
from threading import Thread,Semaphore
from types import IntType

import argparse
import psutil
import subprocess
import time,sys,datetime

import mdlog
import md_shell
import md_tcp_meterpreter
import md_http_meterpreter

CMD_COMMAND = "cmd.exe"
JAVA_COMMAND = "java.exe"
REVERSE_HTTP_SIGNATURE = "ApacheBench"
MONITORING_INTERVAL = 5
DISABLE_INTERVAL = 10
DECEPTION_CYCLE  = 3
DISABLE_DECEPTION= False

""" List Window Process to find CompanyName and Description
    CurrProcess.exe 1.3 by http://www.nirsoft.net
    **TODO - it could be anything else;
    subprocess.call(['CProcess.exe','/stab','ps.dat'])
"""
LIST_PROCESS_FOUT = "_ps.dat"
LIST_PROCESS_TEXT = "_ps2.dat"
LIST_PROCESS = ['CProcess.exe','/stab',LIST_PROCESS_FOUT]
LISTLINE_PROCESS = ['CProcess.exe','/stext',LIST_PROCESS_TEXT]

#prevent long delay of ASCII searching
DEFAULT_MEMORY_TRACE_LINE_LIMIT = 80000 
VEIL_MEMORY_TRACE_LINE_LIMIT = 80000 

def extract_est_conn():
    est_conn_procList = []
    reverse_http_procList = []
    cmd_procList = []
    suspicious_veil_procList = []

    #TODO do something more elaborately 
    reverseFlag = True

    for procitem in psutil.process_iter():
        proc_name = ""
        try:
            pid = procitem.as_dict(attrs=['pid'])['pid']
            proc = psutil.Process(pid)
            proc_name = proc.name()
            if  proc_name == CMD_COMMAND:
                cmd_procList.append(proc)
        
        except: #no process
            pass
            
        connections = proc.connections()
        reverse_conn = {} 
        
        for conn in connections:
            #find only esatablished connections 
            if ((conn.status == 'ESTABLISHED') and (conn.laddr[0]!=conn.raddr[0])):
                est_conn_procList.append(proc)
                break
            #find reverse_http connections
            elif (pid==0 and (conn.status == 'TIME_WAIT') and (conn.laddr[0]!=conn.raddr[0])):
                if (reverse_conn.has_key(conn.raddr[0])):
                    reverse_conn[conn.raddr[0]] += 1
                else:
                    reverse_conn[conn.raddr[0]] = 0

            #find java meterpreter reverse_http connections
            elif ((proc_name == JAVA_COMMAND) and (conn.status == 'CLOSE_WAIT') and (conn.laddr[0]!=conn.raddr[0])):
                reverse_http_procList.append(proc)

        for raddr in reverse_conn.keys():
            if (reverse_conn[raddr] > 5):
                reverseFlag = True
                break
    
    if (reverseFlag):
        find_reverse_http(est_conn_procList,reverse_http_procList)
        find_suspicious_proc(est_conn_procList,suspicious_veil_procList)
        
    return (est_conn_procList,reverse_http_procList,cmd_procList,suspicious_veil_procList)


def find_reverse_http(est_conn_procList,reverse_http_procList):
    pids = []
    for proc in est_conn_procList:
        pids.append(proc.pid)
    
    subprocess.call(LIST_PROCESS)
    fin = open(LIST_PROCESS_FOUT,'r')
   
    for line in fin.readlines():
        row = line.strip().split()
        pid = int(row[1])
        if ((REVERSE_HTTP_SIGNATURE in row) and (pid not in pids)):
            reverse_http_procList.append(psutil.Process(pid))

def find_suspicious_proc(est_conn_procList,suspicious_veil_procList):
    pids = []

    for proc in est_conn_procList:
        pids.append(proc.pid)

    subprocess.call(LISTLINE_PROCESS)
    fin = open(LIST_PROCESS_TEXT,'r')

    keywords = ["Process Name","ProcessID","Company"]
    terms = []
    counter = 0
    
    for line in fin.readlines():
      if (line.find(keywords[counter]) >= 0):
          #print "Found %d", counter
          terms.append(line.split(':')[1].strip())
          counter = (counter + 1) % 3
          if (counter == 0):
              if (terms[2]=='' and terms[0].strip()!='python.exe'):
                  pid = int(terms[1])
                  if (pid not in pids):
                      #print "Suspicious : ", pid
                      suspicious_veil_procList.append(psutil.Process(pid))
              terms = []

def find_meterpreter_trace(pid,rateLimit):
    
    if (System.arch == 'i386' and System.bits==32): 
        try:
            meterpreter_trace_keywords = [['stdapi_railgun_api',False],
                                  ['stdapi_railgun_api_multi',False],
                                  ['stdapi_railgun_memread',False],
                                  ['stdapi_railgun_memwrite',False]
                                 ]
            process = psutil.Process(pid)
            if (process.is_running() and process.name()=='java.exe'):
                meterpreter_trace_keywords = [['class$com$metasploit$meterpreter$stdapi$channel_create_stdapi_fs_file',False],
                                  ['class$com$metasploit$meterpreter$stdapi$channel_create_stdapi_net_tcp_client',False],
                                  ['class$com$metasploit$meterpreter$stdapi$channel_create_stdapi_net_tcp_server',False],
                                  ['class$com$metasploit$meterpreter$stdapi$channel_create_stdapi_net_udp_client',False]
                                 ]                
        except Exception,e:
            pass #suppress no process name
        
        #print "Searching in",pid
        foundIndex = 0
        process = Process(pid)
        line  = 0
 
        #For each ASCII string found in the process memory...
        for address, size, data in process.strings():
            #print "%s: %s" % (HexDump.address(address),data)
            data = data.strip()
            if (data.find(meterpreter_trace_keywords[foundIndex][0]) >= 0):
                meterpreter_trace_keywords[foundIndex][1] = True
                mdlog.print_console(mdlog.SUCCESS_LEVEL,(meterpreter_trace_keywords[foundIndex][0]))
                foundIndex += 1
                
                if foundIndex > len(meterpreter_trace_keywords)-1:
                    break
            line += 1
            if (line > rateLimit):
                return False
        if foundIndex < 3:
            #print "Found: %d" , foundIndex
            return False
        else:
            found = True
            for trace in meterpreter_trace_keywords:
                found = found and trace[1]
            return found
    else:
        return False
        
def verify_debugger(debug_procList,est_conn_procList,reverse_http_procList,cmd_procList):
    inScopeList = []
    
    try:
        estList = []
        for proc in est_conn_procList:
            estList.append(proc.pid)
        for proc in reverse_http_procList:
            estList.append(proc.pid)
        #print "est:",estList
        for proc in cmd_procList:
            #print "cmd pid:" , proc.pid, proc.ppid()
            if proc.ppid() in estList:
                estList.append(proc.pid)            
        
        
        for dbg in debug_procList:
            if (dbg[1]!=None and (dbg[0] in estList)):
                inScopeList.append(dbg[0])
            elif (dbg[1]!=None and (dbg[0] not in estList)):
                dbg[1].stop()
                debug_procList.remove(dbg)
                #print "force stop"
            else:
                debug_procList.remove(dbg)
    except Exception, e:
        mdlog.print_console(mdlog.ERROR_LEVEL,("[-] Error in verification= " + str(e)))
    finally:
        return inScopeList

def isInReverse_HTTP(pid,reverse_http_procList):
    for proc in reverse_http_procList:
        if pid == proc.pid:
            return True
    return False

def retrieve_ps_id(processList):
    pids = []
    for proc in processList:
        pids.append(proc.pid)
    return pids

def main_loop():
    debug_procList = []
    est_conn_procList,reverse_http_procList,cmd_procList,suspicious_veil_procList = extract_est_conn()

    hookcounter = 0
    hookFlag = False
    detachflag = False
    mdlog.print_console(mdlog.INFO_LEVEL,"-------- Start Monitoring ------------")
  
    while ((len(est_conn_procList) > 0) or (len(cmd_procList) > 0)):
        inScopeList = verify_debugger(debug_procList,est_conn_procList,reverse_http_procList,cmd_procList)
        mdlog.print_console(mdlog.INFO_LEVEL,"[*] InscopeList: " + str(inScopeList))
        mdlog.print_console(mdlog.INFO_LEVEL,"[*] Enumerating ESTABLISHED_Process")

        for proc in est_conn_procList:
            traceFlag = False
            try:
                if (proc.pid not in inScopeList):
                    #print "Established %d", proc.pid
                    traceFlag = find_meterpreter_trace(proc.pid,DEFAULT_MEMORY_TRACE_LINE_LIMIT)
            except WindowsError,e:
                pass
            except Exception,e:
                mdlog.print_console(mdlog.ERROR_LEVEL,("[-] Tracing PID:" + str(proc.pid) + " " + str(e)))   
            
            if (traceFlag):
                mdlog.print_console(mdlog.INFO_LEVEL,"[*] tcp_Meterpreter " + str(proc.pid) + " " + str(proc.name) + " " + str(proc.connections()))
                myhandler = md_tcp_meterpreter.hook_handler()
                debug = Debug(myhandler,bKillOnExit=True)
                debug_procList.append([proc.pid,debug])
                thread = Thread(target=intercept_windowapi,args=(debug,proc.pid))
                thread.start()
                time.sleep(1) #sleep for smooth debugger console
                hookFlag = True
                
        traceFlag = False
        
        mdlog.print_console(mdlog.INFO_LEVEL,"[*] Enumerating Reverse_Process") 
        for proc in reverse_http_procList:
            try:
                if (proc.pid not in inScopeList):
                    traceFlag = find_meterpreter_trace(proc.pid,DEFAULT_MEMORY_TRACE_LINE_LIMIT)
            except Exception,e:
                mdlog.print_console(mdlog.ERROR_LEVEL,("[-] Error in tracing " + str(e))) 
                time.sleep(3) #sleep for another access
            
            if (traceFlag):
                try:
                    mdlog.print_console(mdlog.INFO_LEVEL,"[*] reverse_https_Meterpreter " + str(proc.pid) + " " + str(proc.name) + " " + str(proc.connections()))                  
                    myhandler = md_http_meterpreter.hook_handler()
                    debug = Debug(myhandler,bKillOnExit=True)
                    debug_procList.append([proc.pid,debug])
                    thread = Thread(target=intercept_windowapi,args=(debug,proc.pid))
                    thread.start()
                    time.sleep(1) #sleep for smooth debugger console
                    hookFlag = True
                except Exception,e:
                    mdlog.print_console(mdlog.ERROR_LEVEL,("[-] Error in reverse_http managing " + str(e)))

        mdlog.print_console(mdlog.INFO_LEVEL,"[*] Enumerating suspicious Reverse_Process") 
        for proc in suspicious_veil_procList:
            try:
                print "Suspicious %d",proc.pid
                if (proc.pid not in inScopeList):
                    traceFlag = find_meterpreter_trace(proc.pid,VEIL_MEMORY_TRACE_LINE_LIMIT)
            except Exception,e:
                mdlog.print_console(mdlog.ERROR_LEVEL,("[-] Error in tracing " + str(e))) 
                time.sleep(3) #sleep for another access
            
            if (traceFlag):
                try:
                    mdlog.print_console(mdlog.INFO_LEVEL,"[*] kill suspicious reverse_https_Meterpreter " + str(proc.pid) + " " + str(proc.name) + " " + str(proc.connections()))                  
                    vprocess = Process(proc.pid)
                    # Kill the process.
                    vprocess.kill()
                    time.sleep(2) #sleep for smooth debugger console
                    
                except Exception,e:
                    mdlog.print_console(mdlog.ERROR_LEVEL,("[-] Error in suspicious reverse_http managing " + str(e))) 
             
        mdlog.print_console(mdlog.INFO_LEVEL,"[*] Enumerating CMD_Process") 
        est_pids = retrieve_ps_id(est_conn_procList)
        for proc in cmd_procList:
            pid = proc.pid
            parent_pid = proc.ppid()
            if (parent_pid in est_pids and (proc.pid not in inScopeList)):
                print proc.pid, proc.name, proc.connections()
                try:
                    mdlog.print_console(mdlog.INFO_LEVEL,"[*] shell " + str(proc.pid) + " " + str(proc.name) + " " + str(proc.connections()))
                    myhandler = md_shell.hook_handler()
                    debug = Debug(myhandler,bKillOnExit=False)
                    debug_procList.append([proc.pid,debug])
                    thread = Thread(target=intercept_windowapi,args=(debug,proc.pid))
                    thread.start()
                    time.sleep(1) #sleep for smooth debugger console
                    hookFlag = True
                    
                except Exception,e:
                    mdlog.print_console(mdlog.ERROR_LEVEL,("[-] Error in shell managing " + str(e))) 
                    
        intervalStr = "------------ " + str(MONITORING_INTERVAL) + "s ------------ " 
        mdlog.print_console(mdlog.INFO_LEVEL,(intervalStr+str(datetime.datetime.now()))) 

        if (hookFlag):
            hookcounter += 1
        dbg_process = []
        if (DISABLE_DECEPTION and hookcounter % DECEPTION_CYCLE == 0):
            if len(debug_procList) > 0:
                for dbg in debug_procList:
                    if dbg[1]!=None and dbg[1].is_debugee(dbg[0])==False:
                        debug_procList.remove(dbg)
                        dbg[1]=None
                        mdlog.print_console(mdlog.INFO_LEVEL,("[*] debugger has been removed from " + str(dbg[0])))
                    else:  
                        dbg[1].stop()
                        dbg[1].detach_from_all(bIgnoreExceptions=True)
                        mdlog.print_console(mdlog.ERROR_LEVEL,"[-] debugger in PID:"+str(dbg[0])+" was detached" )
                        dbg[1] = None
                    dbg_process.append(dbg[0])
                mdlog.print_console(mdlog.ERROR_LEVEL,"[-] deception is disabled...")
                time.sleep(DISABLE_INTERVAL)
                return dbg_process
        
        time.sleep(MONITORING_INTERVAL)
        if (detachflag==False):
            est_conn_procList,reverse_http_procList,cmd_procList,suspicious_veil_procList = extract_est_conn()
        
    for dbg in debug_procList:
        if dbg[1]!=None:
            dbg[1].stop()
    mdlog.print_console(mdlog.INFO_LEVEL,"-------- End of Monitoring ------------") 
    return 0

def intercept_windowapi(debug,pid):
    try:
        mdlog.print_console(mdlog.SUCCESS_LEVEL,("[+] Hooking " + str(pid))) 
        debug.attach(pid)        
        mdlog.print_console(mdlog.SUCCESS_LEVEL,("[+]   --> Attached " + str(pid))) 
        debug.loop()
    except Exception,e:
        mdlog.print_console(mdlog.ERROR_LEVEL,"Error API Interception :"+str(e))
    finally:
        #debug.stop()
        mdlog.print_console(mdlog.INFO_LEVEL,("[*]   --> Out of intercept loop in PID:" + str(pid))) 

def monitor_main():
    try:
        while (True):
            status = main_loop()
            try:
                for pid in status:
                    Process(pid).kill()
            except:
                pass
            #mdlog.print_console(mdlog.INFO_LEVEL,"[*] out of main loop")
            time.sleep(5)
    except KeyboardInterrupt:
        mdlog.print_console(mdlog.INFO_LEVEL,"[*] Force exit")
    except Exception,e:
        mdlog.print_console(mdlog.ERROR_LEVEL,"[-] Error: ",str(e))
    finally:
        sys.exit(0)

if __name__ == '__main__':

    VERSION = 0.2
    banner = """
 __  __      _   ____  _____ ____ 
|  \/  | ___| |_|  _ \| ____/ ___|
| |\/| |/ _ \ __| | | |  _|| |    
| |  | |  __/ |_| |_| | |__| |___ 
|_|  |_|\___|\__|____/|_____\____|

MetDEC 0.2 - Metasploit <post-exploitation> Deception
             by Pornsook Kornkitichai (alice@incognitolab.com)"""

#print banner

    parser = argparse.ArgumentParser(description="")
    parser.add_argument('--loop','-l',
                        nargs=1,default=5,type=int,
                        help='Run MetDEC with monitoring loop in every n seconds; default loop is 5 seconds')

    parser.add_argument('--idle','-i',
                        nargs=2,default=[0,0],type=int,
                        help='Run MetDEC with the cycle of t1(cycle):deception->t2(seconds):normal->kill')

    parser.add_argument('--baseline','-b',
                        action='store_true',
                        help='[PENDING] Perform baseline analysis for all processes after that it will focus only the new one')

    parser.add_argument('--version','-V',
                        action='store_true',help='Print version number')

    args = parser.parse_args()

    if (args.version):
        print "MetDEC " + str(VERSION)
        exit()

    print banner
    if (type(args.loop) is IntType):
        MONITORING_INTERVAL = args.loop
    else:
        MONITORING_INTERVAL = args.loop[0]
			
    if (args.idle[0] > 0):
        print "running with deception: " + str(args.idle[0]) + " cycles and normal:" + str(args.idle[1]) + " seconds in Loop:" + str(MONITORING_INTERVAL)
        DECEPTION_CYCLE  = args.idle[0]
        DISABLE_INTERVAL = args.idle[1]
        DISABLE_DECEPTION= True
    elif (args.baseline):
        print "MetDEC with baseline and " + " Loop:" + str(args.loop[0])
    else:    
        print "running with loop: %d" % MONITORING_INTERVAL
    
    monitor_main()
