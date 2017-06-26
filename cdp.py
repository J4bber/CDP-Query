#!/usr/bin/python
# cdp.py - gather cdp information, change interface descriptions
#
# Written by: Brian Franklin (brian.franklin@emc.com)
#
# Version 0.1 - Initial Release
# Version 0.2 - Added error checking, summary_cdp_found list,
#               minor bugs fixed, added error logging
# Version 0.3 - Don't change if description already present 
# Version 0.4 - WIP
################################################################


import paramiko
import sys
import time
import os
import os.path
#import pprint
import argparse
import logging
from inspect import currentframe, getframeinfo
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
    logger = logging.getLogger('CDP')
    try:
        outputFilename = path + "/"+ filename
        outfile = open(outputFilename, mode)
        outfile.write(data)
        outfile.close()
    except:
        logger.error(create_logger_message ("Error writing file: "+outputFilename))

    return


def create_logger_message (error):
    '''
    ### Creates a formatted error message
    '''

#    error_msg = "*** "+str(error) +" ***"
    
#    return error_msg
    return str(error)

def multi_command(remote_conn, commands, waitHowLong, waitForString):
    
    ### Only errors are returned
    logger = logging.getLogger('CDP')
    logger.debug(create_logger_message ("Multi_command: "))
    
    for command in commands:
        (error,output)=send_command(remote_conn,command,waitHowLong,waitForString)
        if error:
            return (True,output)
    return (False,"")


def send_command(remote_conn, command, waitHowLong, waitForString):
    '''
    Send command to device

        waitHowLong (in seconds)

    '''
    logger = logging.getLogger('CDP')

    remote_conn.send(command)

    command = command.strip("\n")
    logger.debug(create_logger_message ("Running ("+str(command)+")"+"; Waiting for ("+waitForString+"); Will wait for ("+str(waitHowLong)+") seconds"))

    ### Wait for the command to complete
    timeout = time.time()+waitHowLong
    
    time.sleep(1)
   
    output = " "
    remote_conn.settimeout(15)

    while waitForString not in output: 

        try:
            logger.debug(create_logger_message ("Inside try"))
            output = remote_conn.recv(50000)
        
        except:
            logger.debug(create_logger_message ("("+waitForString+") not found"))
            return (True,"("+waitForString+") not found")

        logger.debug(create_logger_message ("Output: "+str(output)))


        if "AAA_AUTHOR_STATUS_METHOD" in output or "Permission denied" in output:
            logger.error(create_logger_message ("Permissions: Not allowed to execute that command ("+command+")"))
            return (True,"Permissions: Not allowed to execute that command ("+command+")")
        elif "Invalid command at" in output:
            logger.error(create_logger_message ("Invalid: Not allowed to execute that command ("+command+")"))
            return (True,"Invalid: Not allowed to execute that command ("+command+")")
        elif time.time() < timeout:
            logger.debug(create_logger_message ("Checking for timeout "))
            time.sleep(1)
        else:
            logger.warning(create_logger_message ("Command timed out waiting for "+waitForString))
            return (True,"Command timed out waiting for "+waitForString)
        logger.debug(create_logger_message ("Still looking for ("+waitForString+")"))        

    logger.debug(create_logger_message ("Command complete. ("+command+")"))

    return (False,output)


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

        try:
            remote_conn_pre.connect(ip, username=username, password=password,
                            look_for_keys=False, allow_agent=False)
        except:
            logger.error(create_logger_message ("SSH Connection failed for "+ip))
            return (0,0) 

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
        '-overwrite', 
        default=False,
        dest='overwrite',
        action='store_true',   
        help='Overwrite descriptions even if they already exist ' + color.BOLD + '(default: %(default)s)' + color.END)
    
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
        default='/tmp/cdp_output',
        dest='outputPath',
        help='Output path for files ' + color.BOLD + '(default: %(default)s)' + color.END)

    parser.add_argument(
        '-l', 
        default='INFO', 
        dest='logLevel', 
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
        help="Set the logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL') " + color.BOLD + "(default: %(default)s)" + color.END)

    parser.add_argument(
        '-log', 
        default='logfile.log', 
        dest='logFile', 
        help="Set the logfile name. Location will be output path." + color.BOLD + "(default: %(default)s)" + color.END)


    args = parser.parse_args()


    #######################################################################################
    ### Create logging setup
    #######################################################################################

    ### create logger
    logger = logging.getLogger('CDP')

    numLogLevel = getattr(logging,args.logLevel.upper())

    if not isinstance(numLogLevel, int):
        raise ValueError(create_logger_message('Invalid log level: '+args.logLevel))

    logger.setLevel(numLogLevel)

    ### create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(numLogLevel)

    fl = logging.FileHandler(args.outputPath + "/" + args.logFile,"w")

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

    ### add fl to logger
    logger.addHandler(fl)

    logger.debug(create_logger_message("Supplied arguments: "+str(args)))

    #######################################################################################
    ### Pull devices and login information from file
    #######################################################################################
    ### Check if hosts file exists and is readable
    if not (os.path.isfile(args.hostsFile) and os.access(args.hostsFile, os.R_OK)):
        
        logger.critical(create_logger_message("hostsFile "+args.hostsFile + " NOT FOUND!"))
        exit(1)

    credentials = {}


    #######################################################################################
    ### :START: Loop through hostsFile and gather credentials
    #######################################################################################

    logger.info(create_logger_message("Reading "+args.hostsFile))
    with open(args.hostsFile) as f:
        for line in nonblank_lines(f):
            line=line.strip()
            host=line.split(",")[0]
            username=line.split(",")[1]
            password=line.split(",")[2]
            try:
                credentials[host]['username']
                logger.warning(create_logger_message("Duplicate host found ("+host+") skipping"))
                continue
            except KeyError:
                logger.debug(create_logger_message("Host not duplicate ("+host+")"))
                logger.info(create_logger_message("\tAdding "+host+" to credentials list"))
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

        logger.debug(create_logger_message("\tAdding header to cdpCSV"))
        write_file("localHost,localPort,remoteName,remotePort,remoteMgmt\n",args.outputPath + "/",args.cdpCSV,'w')

    #######################################################################################
    ### List of found cdp neighbors for summary file; Create list 
    #######################################################################################
    if args.cdpFound:
        summary_found_cdp = {}

    #######################################################################################
    ### :START Loop 1: Loop through all hosts in credentials file
    #######################################################################################
    for hosts in credentials:
        error_msg=''            
        
        logger.debug(create_logger_message("### :START Loop 1: Loop through all hosts in credentials file"))
        logger.info(create_logger_message("Connecting to " + hosts))

        (remote_conn_pre, remote_conn) = establish_connection(hosts, 
                    credentials[hosts]['username'], credentials[hosts]['password'])

        try:    

        #######################################################################################
        ### :START: Try section:
        #######################################################################################
            logger.debug(create_logger_message("### :START: Try Section:"))
            #######################################################################################
            ### :START: If remote connection open 
            #######################################################################################
            if remote_conn_pre != 0:
                logger.debug(create_logger_message("### :START: If remote connection open "))

                ### Get switch name
                logger.debug(create_logger_message("Getting switch hostname from  " + hosts)) 

                (error,output)=send_command(remote_conn,"sh run | inc hostname|switchname\n",10,"hostname ")
                if error:
                    logger.error(create_logger_message("sh run | inc hostname|switchname"))
                    error_msg = output
                    raise 

                sp=output.split("\n")


                for i in range(len(sp)):
                        sp[i] = sp[i].strip()
                        if 'hostname ' in sp[i]:
                            switchname = sp[i].lstrip('hostname ').rstrip()
                        if 'switchname ' in sp[i]:
                            switchname = sp[i].lstrip('switchname ').rstrip()

                if switchname == '':
                    logger.error(create_logger_message("hostname/switchname not found"))
                    error_msg = "hostname/switchname not found"
                    raise

                ### Turn off --- MORE ---                                                       
                logger.debug(create_logger_message("Turn off --- MORE ---"))  

                (trash1,trash2) = send_command(remote_conn,"\n",5,switchname)

                (error,output) = send_command(remote_conn,"terminal length 0\n",5,switchname)
                if error:
                    logger.error(create_logger_message("terminal length 0"))
                    error_msg = output 
                    raise
                 
                logger.info(create_logger_message("\tCollecting 'show cdp neighbor detail' output...."))  

                (trash1,trash2) = send_command(remote_conn,"\n",5,switchname)


                (error,output) = send_command(remote_conn,"show cdp neighbor detail\n",180,switchname+"#")
                if error:
                    logger.error(create_logger_message("show cdp neighbor detail"))
                    error_msg = output
                    raise 
     
                logger.debug(create_logger_message("Writing show cdp neighbor detail ("+hosts+")"))

                write_file(output,args.outputPath + "/",hosts + "-" + args.cdpSuffix,'w')


                #######################################################################################
                ### :START: Parse SHOW CDP NEIGHBOR DETAIL 
                #######################################################################################
                commandList = []

                if args.change or args.cdpCSV or args.cdpFound:
                    logger.info(create_logger_message("\tParsing 'show cdp neighbor detail' output...."))  

                    logger.debug(create_logger_message("### :START: Parse SHOW CDP NEIGHBOR DETAIL      "))
                    sp = output.split("\n")

                    remoteName = ''
                    localPort = ''
                    network_devices = {}

                    #######################################################################################
                    ### :START: Parse through cdp output 
                    #######################################################################################
                    logger.debug(create_logger_message("### :START: Parse through cdp output    "))
                    for i in range(len(sp)):

                        sp[i] = sp[i].strip()
                        
                        logger.debug(create_logger_message("\tparse line = " + sp[i]))

                        ### Reset at divider                                                            
                        if '----------------' in sp[i]:
                            if remoteName and localPort:

                                logger.debug(create_logger_message("Creating CDP list"))

                                network_devices[localPort] = {}
                                network_devices[localPort]['localPort'] = localPort
                                network_devices[localPort]['remoteName'] = remoteName
                                network_devices[localPort]['remotePort'] = remotePort
                                network_devices[localPort]['remoteMgmt'] = remoteMgmt
                                
                                ### If wanting list of all cdp found devices
                                if args.cdpFound:
                                    summary_found_cdp[remoteName]['mgmt'] = remoteMgmt


                                ### If cdp parsed CSV                                                           
                                if args.cdpCSV:
        
                                    logger.debug(create_logger_message("\tAdding " +hosts+","+localPort+","+remoteName+","+remotePort+","+remoteMgmt+" to "+args.cdpCSV))

                                    write_file(hosts+","+localPort+","+remoteName+","+remotePort+","+remoteMgmt+"\n",args.outputPath + "/",args.cdpCSV,'a')

                                ### If change descriptions
                                if args.change:
                                    (error,desc) = send_command(remote_conn,"sh run interface "+ network_devices[localPort]['localPort'] +" | inc description\n",5,switchname)

                                    logger.debug(create_logger_message(str(error)+" "+desc))

                                    if error or args.overwrite:
                                        ### Previous description not found
                                        logger.info(create_logger_message("\tAdding description for "+hosts+" interface "+network_devices[localPort]['localPort'] + " to command list"))
                                        logger.debug(create_logger_message("Creating command list"))
                                        

                                        description = network_devices[localPort]['localPort'] + " <-> " + network_devices[localPort]['remoteName'] + " " + network_devices[localPort]['remotePort']

                                        logger.debug(create_logger_message("interface " + network_devices[localPort]['localPort'] + "\n" +
                                            "description " + description + "\n"))

                                        commandList.append("interface " + network_devices[localPort]['localPort'] + "\n")
                                        commandList.append("description " + description + "\n")
                                    else:
                                        logger.info(create_logger_message("\tDescription for "+hosts+" interface "+network_devices[localPort]['localPort'] + " will not be modified"))

     
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
                            
                            if args.cdpFound:
                                try:
                                    summary_found_cdp[remoteName]['mgmt']
                                    logger.debug(create_logger_message("checking if "+remoteName+" already in summary list"))
                                    continue
                                except KeyError:
                                    logger.debug(create_logger_message(remoteName+" NOT already in summary list.  Adding"))
                                    summary_found_cdp[remoteName] = {}
                                    pass

                            logger.debug(create_logger_message("remoteName = " + remoteName))


                        ### Process in/out ports
                        elif 'Interface: ' in sp[i]:
                            localPort = sp[i].lstrip('Interface: ').split(',')[0]
                            remotePort = sp[i].split('port): ')[1] 
                                
                            logger.debug(create_logger_message("localPort = " + localPort + "; remotePort = " + remotePort))


                        ### Process MGMT address
                        elif 'Mgmt' in sp[i]:
                            
                            remoteMgmt = sp[i+1].lstrip('IPv4 Address: ').rstrip()

                            logger.debug(create_logger_message("mgmt ip = " + remoteMgmt))

                    logger.debug(create_logger_message("### :END: Parse through cdp output"))
                    #######################################################################################
                    ### :END: Parse through cdp output 
                    #######################################################################################

                    #######################################################################################
                    ### :START: Grab last entry if there
                    #######################################################################################

                    if remoteName and localPort:
                        logger.debug(create_logger_message("### :START: Grab last entry if there"))

                        logger.debug(create_logger_message("\tAdding last entry " + remoteName + " " +localPort))

                        network_devices[localPort] = {}
                        network_devices[localPort]['remoteName'] = remoteName
                        network_devices[localPort]['localPort'] = localPort
                        network_devices[localPort]['remotePort'] = remotePort
                        network_devices[localPort]['remoteMgmt'] = remoteMgmt

                        ### If wanting list of all cdp found devices
                        if args.cdpFound:
                            summary_found_cdp[remoteName]['mgmt'] = remoteMgmt

                        ### If cdp parsed CSV
                        if args.cdpCSV:

                            logger.debug(create_logger_message("Adding " +hosts+","+localPort+","+remoteName+","+remotePort+","+remoteMgmt+" to cdpCSV"))
                            write_file(hosts+","+localPort+","+remoteName+","+remotePort+","+remoteMgmt+"\n",args.outputPath + "/",args.cdpCSV,'a')

                        ### If change descriptions
                        if args.change:

                            (error,desc) = send_command(remote_conn,"sh run interface "+ network_devices[localPort]['localPort'] +" | inc description\n",5,"description ")

                            logger.debug(create_logger_message(str(error)+desc))

                            if error or args.overwrite:
                                ### Previous description not found
                                logger.info(create_logger_message("\tAdding description for "+hosts+" interface "+network_devices[localPort]['localPort'] + " to command list"))
                                logger.debug(create_logger_message("Creating command list"))
                                

                                description = network_devices[localPort]['localPort'] + " <-> " + network_devices[localPort]['remoteName'] + " " + network_devices[localPort]['remotePort']

                                logger.debug(create_logger_message("interface " + network_devices[localPort]['localPort'] + "\n" +
                                    "description " + description + "\n"))

                                commandList.append("interface " + network_devices[localPort]['localPort'] + "\n")
                                commandList.append("description " + description + "\n")

                            else:
                                logger.info(create_logger_message("\tDescription for "+hosts+" interface "+network_devices[localPort]['localPort'] + " will not be modified"))
                        logger.debug(create_logger_message("### :END: Grab last entry if there"))

                    #######################################################################################
                    ### :END: Grab last entry if there
                    #######################################################################################
                logger.debug(create_logger_message("### :END: Parse SHOW CDP NEIGHBOR DETAIL"))
                #######################################################################################
                ### :END: Parse SHOW CDP NEIGHBOR DETAIL 
                #######################################################################################


                logger.debug(create_logger_message(commandList))

                if args.change and commandList:
                    ### Make changes and save

                    commandList.insert(0,"configure terminal\n")
                    commandList.append("end\n")

                    logger.info(create_logger_message("\tChanging configuration... PLEASE WAIT..."))

                    (error,output) = multi_command(remote_conn,commandList,10,switchname)
                    if error:
                        logger.error(create_logger_message("Error: "+commandList))
                        error_msg = output
                        raise                                    

                    logger.info(create_logger_message("\tSaving configuration... PLEASE WAIT..."))
                    logger.debug(create_logger_message("Saving config on "+hosts))

                    (error,output) = send_command(remote_conn,"copy run start\n",180,switchname)
                    if error:
                        logger.error(create_logger_message("copy run start"))
                        error_msg = output
                        raise
    
                    logger.debug(create_logger_message("FINISHED changing descriptions on "+hosts))
                logger.debug(create_logger_message("### :END: Grab last entry if there"))

                ### Save done hosts
                logger.info(create_logger_message("\t"+hosts+" completed."))
                write_file(hosts+","+credentials[hosts]['username']+","+credentials[hosts]['password']+"\n",args.outputPath,args.doneHostsFile,'a')
            
                logger.debug(create_logger_message("### :END: If remote connection open"))
            #######################################################################################
            ### :END: If remote connection open 
            #######################################################################################

            else:
                logger.error(create_logger_message("end of try section for remote_conn_pre != 0.  Should I be here?"))
                error_msg = "end of try section for remote_conn_pre != 0.  Should I be here?" 
                raise   

            logger.debug(create_logger_message("### :END: Try Section:"))

        except:
            #######################################################################################
            ### :START: EXCEPT Try section:
            #######################################################################################

            ### Can't login to host
            logger.error(create_logger_message("### :Except Section:"))
            logger.error(create_logger_message("### "+ str(sys.exc_info())))
            logger.info(create_logger_message("Error on "+hosts+". Adding to "+args.badHostsFile))
            write_file(hosts+","+credentials[hosts]['username']+","+credentials[hosts]['password']+","+error_msg,args.outputPath,args.badHostsFile,"a")
            error_msg=''            

        finally:
            ### Close ssh connection
            logger.debug(create_logger_message("### :Finally Section:"))
            if remote_conn_pre != 0:
                logger.info(create_logger_message("\tClosing ssh connection"))
                remote_conn_pre.close()

        logger.debug(create_logger_message("### :END Loop 1: Loop through all hosts in credentials file"))
        #######################################################################################
        ### :END Loop 1: Loop through all hosts in credentials file
        #######################################################################################
    

    if args.cdpFound:
        logger.debug(create_logger_message("Creating "+args.cdpFound))
        logger.debug(create_logger_message("List contains: "+str(summary_found_cdp)))

        ### Write cdp found file
        for found in summary_found_cdp:
            logger.debug(create_logger_message("Adding to "+args.cdpFound+" "+found))
            write_file(found+","+summary_found_cdp[found]['mgmt']+"\n",args.outputPath,args.cdpFound,'a')            

    logger.info(create_logger_message("DONE with all hosts!"))


if __name__ == "__main__":
    main()

