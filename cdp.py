#!/usr/bin/python
# cdp.py - gather cdp information, change interface descriptions
#
# Written by: Brian Franklin (brian.franklin@emc.com)
#
# Version 0.1 - Initial Release
#
################################################################


import paramiko
import sys
import time
import os
import os.path
import pprint
import argparse
import logging
from colorlog import ColoredFormatter
from contextlib import contextmanager
@contextmanager


class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'


def nonblank_lines(f):
    for l in f:
        line = l.rstrip()
        if line:
            yield line


def write_file(data,path,filename,mode):
    outputFilename = path + "/"+ filename
    outfile = open(outputFilename, mode)
    outfile.write(data)
    outfile.close()

    return


def create_error_message (error):
    '''
    ### Creates a formatted error message
    '''
    error_msg = "*** "+str(error) +" ***"
    
    return error_msg


def skip_host(host,username,password,opath,bfile):
    logger = logging.getLogger('CDP')

    logger.warning(create_error_message ("Check credentials and permissions on "+host+". Problem trying to execute command. Skipping host."))
    write_file(host+","+username+","+password+"\n",opath,bfile,'a')

    return


def multi_command(remote_conn, commands, waitHowLong, waitForString):
    
    ### Only errors are returned
    logger = logging.getLogger('CDP')
    logger.debug(create_error_message ("Multi_command: "))
    
    for command in commands:
        if (send_command(remote_conn,command,waitHowLong,waitForString)) == 1:
            return 1
    return 0


def send_command(remote_conn, command, waitHowLong, waitForString):
    '''
    Send command to device

        waitHowLong (in seconds)

    '''
    logger = logging.getLogger('CDP')

    remote_conn.send(command)

    command = command.strip("\n")
    logger.debug(create_error_message ("Running ("+str(command)+")"+"; Waiting for ("+waitForString+"); Will wait for ("+str(waitHowLong)+") seconds"))

    ### Wait for the command to complete
    timeout = time.time()+waitHowLong
    
    time.sleep(1)
   
    output = " "


    while waitForString not in output: 
        output = remote_conn.recv(50000)
        logger.debug(create_error_message ("Output: "+str(output)))


        if "AAA_AUTHOR_STATUS_METHOD" in output or "Permission denied" in output:
            ### try to get out of any mode you are in & jump out
            remote_conn.send("end\n")
            logger.error(create_error_message ("Permissions: Not allowed to execute that command ("+command+")"))
            return 1
        elif "Invalid command at" in output:
            logger.error(create_error_message ("Invalid: Not allowed to execute that command ("+command+")"))
            return 1
        elif time.time() < timeout:
            logger.debug(create_error_message ("Checking for timeout "))
            time.sleep(1)
        else:
            logger.debug(create_error_message ("Command timed out waiting for "+waitForString))
            return 1
        logger.debug(create_error_message ("Still looking for ("+waitForString+")"))        

    logger.debug(create_error_message ("Command complete. ("+command+")"))

    return output


def establish_connection(ip, username='', password=''):
    '''
    Use Paramiko to establish an SSH channel to the device
    Must return both return_conn_pre and return_conn so that the SSH
    connection is not garbage collected
    '''
    try:
        remote_conn_pre = paramiko.SSHClient()
        remote_conn_pre.set_missing_host_key_policy(
            paramiko.AutoAddPolicy())

        remote_conn_pre.connect(ip, username=username, password=password,
                            look_for_keys=False, allow_agent=False)

        remote_conn = remote_conn_pre.invoke_shell()
    except paramiko.AuthenticationException:
        return (0,0)

    ### Clear banner and prompt
    output = remote_conn.recv(65535)

    return (remote_conn_pre, remote_conn)



def main():


    ### Set all available CLI arguments

    parser = argparse.ArgumentParser(description=color.RED+color.BOLD + '*** This is a script to gather CDP information per host and change the interface description (if requested) based on this information ***** Script by Brian Franklin ***'+color.END)

    parser.add_argument(
        '-change', 
        default=False,
        dest='change',
        action='store_true',   
        help='Change descriptions ' + color.BOLD + '(default: %(default)s)' + color.END)
    
    parser.add_argument(
        '-cdpSuffix', 
        default='cdpDetailOutput.txt',
        dest='cdpSuffix',
        help='Suffix on "show cdp neighbor detail" output file ' + color.BOLD + '(default: %(default)s)' + color.END)

    parser.add_argument(
        '-hosts', 
        default='hosts.csv',
        dest='hostsFile',
        help='Hosts file name ' + color.BOLD + '(default: %(default)s)' + color.END)

    parser.add_argument(
        '-bad', 
        default='bad.hosts.csv',
        dest='badHostsFile',
        help='Hosts that have login issues ' + color.BOLD + '(default: %(default)s)' + color.END)

    parser.add_argument(
        '-done', 
        default='done.hosts.csv',
        dest='doneHostsFile',
        help='Hosts that have finished ' + color.BOLD + '(default: %(default)s)' + color.END)

    parser.add_argument(
        '-cdpFound', 
        dest='cdpFound',
        help='Filename for parsed list of cdp neighbors found ' + color.BOLD + '(default: %(default)s)' + color.END)

    parser.add_argument(
        '-cdpCSV', 
        dest='cdpCSV',
        help='Filename for parsed list of cdp neighbors with details ' + color.BOLD + '(default: %(default)s)' + color.END)

    parser.add_argument(
        '-outputPath', 
        default='./output',
        dest='outputPath',
        help='Output path for files ' + color.BOLD + '(default: %(default)s)' + color.END)

    parser.add_argument(
        '-l', 
        default='WARNING', 
        dest='logLevel', 
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
        help="Set the logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL') " + color.BOLD + "(default: %(default)s)" + color.END)


    args = parser.parse_args()

    #######################################################################################
    ### Create logging setup
    #######################################################################################

    ### create logger
    logger = logging.getLogger('CDP')

    numLogLevel = getattr(logging,args.logLevel.upper())

    if not isinstance(numLogLevel, int):
        raise ValueError(create_error_message('Invalid log level: '+args.logLevel))

    logger.setLevel(numLogLevel)

    ### create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(numLogLevel)

    ### create formatter
    formatter = ColoredFormatter(
            "   %(log_color)s%(asctime)-22s%(levelname)-8s%(reset)s %(funcName)-15s %(log_color)s%(message)s%(reset)s",
            datefmt='%m/%d/%Y %H:%M:%S',
            reset=True,
            log_colors={
                    'DEBUG':    'cyan',
                    'INFO':     'green',
                    'WARNING':  'yellow',
                    'ERROR':    'red',
                    'CRITICAL': 'red,bg_white',
            },
            secondary_log_colors={},
            style='%'
    )

    ### add formatter to ch
    ch.setFormatter(formatter)

    ### add ch to logger
    logger.addHandler(ch)

    logger.debug(create_error_message("Supplied arguments: "+str(args)))

    #######################################################################################
    ### Pull devices and login information from file
    #######################################################################################
    ### Check if hosts file exists and is readable
    if not (os.path.isfile(args.hostsFile) and os.access(args.hostsFile, os.R_OK)):
        
        logger.critical(create_error_message("hostsFile "+args.hostsFile + " NOT FOUND!"))
        exit(1)

    credentials = {}

    #######################################################################################
    ### :START: Loop through hostsFile and gather credentials
    #######################################################################################
    with open(args.hostsFile) as f:
        for line in nonblank_lines(f):
            line=line.strip()
            host=line.split(",")[0]
            username=line.split(",")[1]
            password=line.split(",")[2]
            try:
                credentials[host]['username']
                logger.warning(create_error_message("Duplicate host found ("+host+") skipping"))
                continue
            except KeyError:
                logger.debug(create_error_message("Host not duplicate ("+host+")"))
                pass

            credentials[host]={}
            credentials[host]['username'] = username
            credentials[host]['password'] = password
    #######################################################################################
    ### :END: Loop through hostsFile and gather credentials
    #######################################################################################

    #######################################################################################
    ### If cdp parsed CSV, add header
    #######################################################################################

    if args.cdpCSV:

        logger.debug(create_error_message("\tAdding header to cdpCSV"))
        write_file("localHost,localPort,remoteName,remotePort,remoteMgmt\n",args.outputPath + "/",args.cdpCSV,'w')

    #######################################################################################
    ### List of found cdp neighbors for summary file; Create list 
    #######################################################################################
    if args.cdpFound:
        summary_found_cdp = []

    #######################################################################################
    ### :START Loop 1: Loop through all hosts in credentials file
    #######################################################################################
    for hosts in credentials:

        logger.debug(create_error_message("### :START Loop 1: Loop through all hosts in credentials file"))
        logger.debug(create_error_message("Connecting to " + hosts))

        (remote_conn_pre, remote_conn) = establish_connection(hosts, 
                    credentials[hosts]['username'], credentials[hosts]['password'])

        try:    

        #######################################################################################
        ### :START: Try section:
        #######################################################################################

            logger.debug(create_error_message("### :START: Try Section:"))

            #######################################################################################
            ### :START: If remote connection open 
            #######################################################################################
            if remote_conn_pre != 0:
                logger.debug(create_error_message("### :START: If remote connection open "))

                ### Get switch name
                logger.debug(create_error_message("Getting switch hostname from  " + hosts)) 

                output=send_command(remote_conn,"sh run | inc hostname\n",10,"hostname ")
                if output == 1:
                    logger.error(create_error_message("sh run | inc hostname"))
                    #skip_host(hosts,credentials[hosts]['username'],credentials[hosts]['password'],args.outputPath,args.badHostsFile)
                    raise 

                sp=output.split("\n")


                for i in range(len(sp)):
                        sp[i] = sp[i].strip()
                        if 'hostname ' in sp[i]:
                            switchname = sp[i].lstrip('hostname ').rstrip()
                            #break

                ### Turn off --- MORE ---                                                       
                logger.debug(create_error_message("Turn off --- MORE ---"))  
                trashcan = send_command(remote_conn,"\n",5,switchname)


                if (send_command(remote_conn,"terminal length 0\n",5,switchname)) == 1:
                    logger.error(create_error_message("terminal length 0"))
                    #skip_host(hosts,credentials[hosts]['username'],credentials[hosts]['password'],args.outputPath,args.badHostsFile)
                    raise
                 
                logger.debug(create_error_message("Collecting 'show cdp neighbor detail' output...."))  

                trashcan = send_command(remote_conn,"\n",5,switchname)
                output = send_command(remote_conn,"show cdp neighbor detail\n",3600,switchname+"#")
                if output == 1:
                    logger.error(create_error_message("show cdp neighbor detail"))
                    #skip_host(hosts,credentials[hosts]['username'],credentials[hosts]['password'],args.outputPath,args.badHostsFile)
                    raise 
     
                logger.debug(create_error_message("Writing show cdp neighbor detail ("+hosts+")"))

                write_file(output,args.outputPath + "/",hosts + "-" + args.cdpSuffix,'w')


                #######################################################################################
                ### :START: if args.change or args.cdpCSV 
                #######################################################################################
                if args.change or args.cdpCSV:
                    logger.debug(create_error_message("### :START: if args.change or args.cdpCSV     "))
                    sp = output.split("\n")

                    remoteName = ''
                    localPort = ''
                    network_devices = {}
                    commandList = []

                    #######################################################################################
                    ### :START Loop 2: for i in range(len(sp)):  ### Parse through cdp output 
                    #######################################################################################
                    for i in range(len(sp)):
                        logger.debug(create_error_message("### :START Loop 2: for i in range(len(sp)):  ### Parse through cdp output"))

                        sp[i] = sp[i].strip()
                        
                        logger.debug(create_error_message("\tline = " + sp[i]))

                        ### Reset at divider                                                            
                        if '----------------' in sp[i]:
                            if remoteName and localPort:

                                logger.debug(create_error_message("Creating CDP list"))

                                network_devices[localPort] = {}
                                network_devices[localPort]['localPort'] = localPort
                                network_devices[localPort]['remoteName'] = remoteName
                                network_devices[localPort]['remotePort'] = remotePort
                                network_devices[localPort]['remoteMgmt'] = remoteMgmt
                                
                                ### If cdp parsed CSV                                                           
                                if args.cdpCSV:
        
                                    logger.debug(create_error_message("\tAdding " +hosts+","+localPort+","+remoteName+","+remotePort+","+remoteMgmt+" to "+args.cdpCSV))

                                    write_file(hosts+","+localPort+","+remoteName+","+remotePort+","+remoteMgmt+"\n",args.outputPath + "/",args.cdpCSV,'a')

                                ### If change descriptions
                                if args.change:

                                    logger.debug(create_error_message("Creating command list"))
                                    
                                    commandList.append('configure terminal\n')

                                    description = network_devices[localPort]['localPort'] + " <-> " + network_devices[localPort]['remoteName'] + " " + network_devices[localPort]['remotePort']

                                    logger.debug(create_error_message("interface " + network_devices[localPort]['localPort'] + "\n" +
                                        "description " + description + "\n"))

                                    commandList.append("interface " + network_devices[localPort]['localPort'] + "\n")
                                    commandList.append("description " + description + "\n")

                                    logger.debug(create_error_message("Exiting config mode"))

                                    commandList.append("end\n")

                                    if (multi_command(remote_conn,commandList,10,switchname)):
                                        logger.debug(create_error_message("Error: "+commandList))
                                        #skip_host(hosts,credentials[hosts]['username'],credentials[hosts]['password'],args.outputPath,args.badHostsFile)
                                        raise                                    
     
                            ### Reset cdp variables
                            localPort = ''
                            remoteName = ''
                            remotePort = ''
                            remotePlatform = ''
                            remoteMgmt = ''

                        ### Process remote hostname       
                        elif 'Device ID:' in sp[i]:

                            remoteName = sp[i].split('Device ID:')[1]
                            remoteName = remoteName.split('(')[0]
                            
                            if args.cdpFound and (remoteName not in summary_found_cdp):
                                summary_found_cdp.append(remoteName)

                            logger.debug(create_error_message("remoteName = " + remoteName))


                        ### Process in/out ports
                        elif 'Interface: ' in sp[i]:
                            localPort = sp[i].lstrip('Interface: ').split(',')[0]
                            remotePort = sp[i].split('port): ')[1] 
                                
                            logger.debug(create_error_message("localPort = " + localPort + "; remotePort = " + remotePort))


                        ### Process MGMT address
                        elif 'Mgmt' in sp[i]:
                            
                            remoteMgmt = sp[i+1].lstrip('IPv4 Address: ').rstrip()

                            logger.debug(create_error_message("mgmt ip = " + remoteMgmt))

                    logger.debug(create_error_message("### :END Loop 2: for i in range(len(sp)):  ### Parse through cdp output"))
                    #######################################################################################
                    ### :END Loop 2: for i in range(len(sp)):  ### Parse through cdp output 
                    #######################################################################################
                logger.debug(create_error_message("### :END: if args.change or args.cdpCSV"))
                #######################################################################################
                ### :END: if args.change or args.cdpCSV 
                #######################################################################################

                #######################################################################################
                ### :START: Grab last entry if there
                #######################################################################################

                if remoteName and localPort:
                    logger.debug(create_error_message("### :START: Grab last entry if there"))

                    logger.debug(create_error_message("\tAdding last entry " + remoteName + " " +localPort))

                    network_devices[localPort] = {}
                    network_devices[localPort]['remoteName'] = remoteName
                    network_devices[localPort]['localPort'] = localPort
                    network_devices[localPort]['remotePort'] = remotePort
                    network_devices[localPort]['remoteMgmt'] = remoteMgmt

                    ### If cdp parsed CSV
                    if args.cdpCSV:

                        logger.debug(create_error_message("\tAdding " +hosts+","+localPort+","+remoteName+","+remotePort+","+remoteMgmt+" to cdpCSV"))
                        write_file(hosts+","+localPort+","+remoteName+","+remotePort+","+remoteMgmt+"\n",args.outputPath + "/",args.cdpCSV,'a')

                    ### If change descriptions
                    if args.change:

                        logger.debug(create_error_message("Creating command list"))
                        
                        commandList.append('configure terminal\n')

                        description = network_devices[localPort]['localPort'] + " <-> " + network_devices[localPort]['remoteName'] + " " + network_devices[localPort]['remotePort']

                        logger.debug(create_error_message("interface " + network_devices[localPort]['localPort'] + "\n" +
                            "description " + description + "\n"))

                        commandList.append("interface " + network_devices[localPort]['localPort'] + "\n")
                        commandList.append("description " + description + "\n")

                        logger.debug(create_error_message("Exiting config mode"))

                        commandList.append("end\n")

                        if (multi_command(remote_conn,commandList,10,switchname)):
                            logger.error(create_error_message(commandList))
                            #skip_host(hosts,credentials[hosts]['username'],credentials[hosts]['password'],args.outputPath,args.badHostsFile)
                            raise                                    

                #######################################################################################
                ### :END: Grab last entry if there
                #######################################################################################

                if args.change:

                    logger.debug(create_error_message("Saving config on "+hosts))

                    output = send_command(remote_conn,"copy run start\n",180,switchname)
                    if (output == 1):
                        logger.error(create_error_message("copy run start"))
                        #skip_host(hosts,credentials[hosts]['username'],credentials[hosts]['password'],args.outputPath,args.badHostsFile)
                        raise
    
                    logger.debug(create_error_message("FINISHED changing descriptions on "+hosts))
                logger.debug(create_error_message("### :END: Grab last entry if there"))

                ### Save done hosts
                logger.debug(create_error_message("\tAdding done host ("+hosts+")"))
                write_file(hosts+","+credentials[hosts]['username']+","+credentials[hosts]['password']+"\n",args.outputPath,args.doneHostsFile,'a')
            
                logger.debug(create_error_message("### :END: If remote connection open"))
            #######################################################################################
            ### :END: If remote connection open 
            #######################################################################################

            else:
                raise   
                ### Can't login to host
                #skip_host(hosts,credentials[hosts]['username'],credentials[hosts]['password'],args.outputPath,args.badHostsFile)

            logger.debug(create_error_message("### :END: Try Section:"))

        except:
            #######################################################################################
            ### :START: EXCEPT Try section:
            #######################################################################################

            ### Can't login to host
            logger.debug(create_error_message("### :Except Section:"))
            logger.debug(create_error_message("### "+ str(sys.exc_info())))
            skip_host(hosts,credentials[hosts]['username'],credentials[hosts]['password'],args.outputPath,args.badHostsFile)

        finally:
            ### Close ssh connection
            logger.debug(create_error_message("### :Finally Section:"))
            remote_conn_pre.close()

        logger.debug(create_error_message("### :END Loop 1: Loop through all hosts in credentials file"))
        #######################################################################################
        ### :END Loop 1: Loop through all hosts in credentials file
        #######################################################################################
    

    if args.cdpFound:
        logger.debug(create_error_message("Creating "+args.cdpFound))
        logger.debug(create_error_message("\tList contains: "+str(summary_found_cdp)))

        ### Write cdp found file
        for found in summary_found_cdp:
            logger.debug(create_error_message("\tAdding "+found))
            write_file(found+"\n",args.outputPath,args.cdpFound,'w')            

    logger.debug(create_error_message("DONE with all hosts!"))


if __name__ == "__main__":
    main()

