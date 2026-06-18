import sys
import os
import struct
import base64
import datetime
import time
import binascii
import pcap
import re
from socket import inet_ntop, AF_INET6, inet_ntoa 
import status
from collections import Counter

def decodeA11(xdr,raw,flush):
    xdr['display'] += ', A11'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Lac'], xdr['Network'] = '0','0','0','3'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''
    found = True
    i = 0
    rawLength = len(raw)
    nextByte = struct.unpack('!B',raw[i:i+1])[0]
    if nextByte == 1:       # A11_REGISTRATION_REQUEST
        if xdr['sip'][len(xdr['sip'])-1] not in pcfIP: pcfIP.append(xdr['sip'][len(xdr['sip'])-1]) 
        if xdr['dip'][len(xdr['dip'])-1] not in pdsnIP: pdsnIP.append(xdr['dip'][len(xdr['dip'])-1]) 
        xdr['PCF_ip'] = xdr['sip'][len(xdr['sip'])-1]
        xdr['PDSN_ip'] = xdr['dip'][len(xdr['dip'])-1]
        xdr['msgType'] = 486
        print(xdr['display'],xdr['msgType'],'A11_REGISTRATION_REQUEST')
        xdr['dir'] = '0'
        i += 1
        nextByte = struct.unpack('!B',raw[i:i+1])[0]   # Flags = [0AH, 8AH]
        if nextByte not in (10,138):
            found = False
        else:
            i += 3                                     # skip Lifetime = [00 00H to FF FEH]
            nextByte = struct.unpack('!I',raw[i:i+4])[0]  # Home Address = [00 00 00 00H]
            if nextByte != 0:
                found = False
            else:
                i += 20
    elif nextByte == 3:     # A11_REGISTRATION_REPLY
        if xdr['sip'][len(xdr['sip'])-1] not in pdsnIP: pdsnIP.append(xdr['sip'][len(xdr['sip'])-1]) 
        if xdr['dip'][len(xdr['dip'])-1] not in pcfIP: pcfIP.append(xdr['dip'][len(xdr['dip'])-1]) 
        xdr['PCF_ip'] = xdr['dip'][len(xdr['dip'])-1]
        xdr['PDSN_ip'] = xdr['sip'][len(xdr['sip'])-1]
        xdr['msgType'] = 487
        print(xdr['display'],xdr['msgType'],'A11_REGISTRATION_REPLY')
        xdr['dir'] = '1'
        i += 1
        nextByte = struct.unpack('!B',raw[i:i+1])[0]   # Code = [00H, 80H, 81H, 82H, 83H, 85H, 86H, 88H, 89H, 8AH, 8DH]
        xdr['Cause'] = nextByte
        if nextByte not in (0,128,129,130,131,133,134,136,137,138,141):
            found = False
        else:
            i += 3                                     # skip Lifetime = [00 00H to FF FEH]
            nextByte = struct.unpack('!I',raw[i:i+4])[0]  # Home Address = [00 00 00 00H]
            if nextByte != 0:
                found = False
            else:
                i += 16
    elif nextByte == 20:    # A11_REGISTRATION_UPDATE
        if xdr['dip'][len(xdr['dip'])-1] not in pcfIP: pcfIP.append(xdr['dip'][len(xdr['dip'])-1]) 
        if xdr['sip'][len(xdr['sip'])-1] not in pdsnIP: pdsnIP.append(xdr['sip'][len(xdr['sip'])-1]) 
        xdr['PCF_ip'] = xdr['dip'][len(xdr['dip'])-1]
        xdr['PDSN_ip'] = xdr['sip'][len(xdr['sip'])-1]
        xdr['msgType'] = 488
        print(xdr['display'],xdr['msgType'],'A11_REGISTRATION_UPDATE')
        xdr['dir'] = '1'
        i += 1
        nextByte1,nextByte2,nextByte3 = struct.unpack('!3B',raw[i:i+3])   # Reserved = [00 00 00H]
        if nextByte1+nextByte2+nextByte3 != 0:
            found = False
        else:
            i += 3
            nextByte = struct.unpack('!I',raw[i:i+4])[0]  # Home Address = [00 00 00 00H]
            if nextByte != 0:
                found = False
            else:
                i += 16
    elif nextByte == 21:    # A11_REGISTRATION_ACKNOWLEDGE
        if xdr['sip'][len(xdr['sip'])-1] not in pcfIP: pcfIP.append(xdr['sip'][len(xdr['sip'])-1]) 
        if xdr['dip'][len(xdr['dip'])-1] not in pdsnIP: pdsnIP.append(xdr['dip'][len(xdr['dip'])-1]) 
        xdr['PCF_ip'] = xdr['sip'][len(xdr['sip'])-1]
        xdr['PDSN_ip'] = xdr['dip'][len(xdr['dip'])-1]
        xdr['msgType'] = 489
        print(xdr['display'],xdr['msgType'],'A11_REGISTRATION_ACKNOWLEDGE')
        xdr['dir'] = '0'
        i += 1
        nextByte = struct.unpack('!H',raw[i:i+2])[0]   # Reserved = [00 00H]
        if nextByte != 0:
            found = False
        else:
            i += 2
            nextByte = struct.unpack('!B',raw[i:i+1])[0]  # Status = [00H, 80H, 83H, 85H, 86H]
            xdr['Cause'] = nextByte
            if nextByte not in (0,128,131,133,134):
                found = False
            else:
                i += 1
                nextByte = struct.unpack('!I',raw[i:i+4])[0]  # Home Address = [00 00 00 00H]
                if nextByte not in (0,128,131,133,134):
                    found = False
                else:
                    i += 16
    elif nextByte == 22:    # A11_SESSION_UPDATE
        if xdr['dip'][len(xdr['dip'])-1] not in pcfIP: pcfIP.append(xdr['dip'][len(xdr['dip'])-1]) 
        if xdr['sip'][len(xdr['sip'])-1] not in pdsnIP: pdsnIP.append(xdr['sip'][len(xdr['sip'])-1]) 
        xdr['PCF_ip'] = xdr['dip'][len(xdr['dip'])-1]
        xdr['PDSN_ip'] = xdr['sip'][len(xdr['sip'])-1]
        xdr['msgType'] = 490
        print(xdr['display'],xdr['msgType'],'A11_SESSION_UPDATE')
        xdr['dir'] = '1'
        i += 1
        nextByte1,nextByte2,nextByte3 = struct.unpack('!3B',raw[i:i+3])   # Reserved = [00 00 00H]
        if nextByte1+nextByte2+nextByte3 != 0:
            found = False
        else:
            i += 3
            nextByte = struct.unpack('!I',raw[i:i+4])[0]  # Home Address = [00 00 00 00H]
            if nextByte != 0:
                found = False
            else:
                i += 16
    elif nextByte == 23:    # A11_SESSION_UPDATE_ACKNOWLEDGE
        if xdr['sip'][len(xdr['sip'])-1] not in pcfIP: pcfIP.append(xdr['sip'][len(xdr['sip'])-1]) 
        if xdr['dip'][len(xdr['dip'])-1] not in pdsnIP: pdsnIP.append(xdr['dip'][len(xdr['dip'])-1]) 
        xdr['PCF_ip'] = xdr['sip'][len(xdr['sip'])-1]
        xdr['PDSN_ip'] = xdr['dip'][len(xdr['dip'])-1]
        xdr['msgType'] = 491
        print(xdr['display'],xdr['msgType'],'A11_SESSION_UPDATE_ACKNOWLEDGE')
        xdr['dir'] = '0'
        i += 1
        nextByte = struct.unpack('!H',raw[i:i+2])[0]   # Reserved = [00 00H]
        if nextByte != 0:
            found = False
        else:
            i += 2
            nextByte = struct.unpack('!B',raw[i:i+1])[0]  # Status = [00H, 80H, 83H, 85H, 86H, C9H]
            xdr['Cause'] = nextByte
            if nextByte not in (0,128,131,133,134,201):
                found = False
            else:
                i += 1
                nextByte = struct.unpack('!I',raw[i:i+4])[0]  # Home Address = [00 00 00 00H]
                if nextByte not in (0,128,131,133,134):
                    found = False
                else:
                    i += 16
    elif nextByte == 24:    # A11_CAPABILITIES_INFO
        xdr['msgType'] = 492
        print(xdr['display'],xdr['msgType'],'A11_CAPABILITIES_INFO')
        if xdr['sip'][len(xdr['sip'])-1] in pcfIP or xdr['dip'][len(xdr['dip'])-1] in pdsnIP:
            xdr['dir'] = '0'
            xdr['PCF_ip'] = xdr['sip'][len(xdr['sip'])-1]
            xdr['PDSN_ip'] = xdr['dip'][len(xdr['dip'])-1]
        else:
            xdr['dir'] = '1'
            xdr['PCF_ip'] = xdr['dip'][len(xdr['dip'])-1]
            xdr['PDSN_ip'] = xdr['sip'][len(xdr['sip'])-1]
        i += 1
        nextByte1,nextByte2,nextByte3 = struct.unpack('!3B',raw[i:i+3])   # Reserved = [00 00H]
        if nextByte1+nextByte2+nextByte3 != 0:
            found = False
        else:
            i += 3
            nextByte = struct.unpack('!I',raw[i:i+4])[0]  # Home Address = [00 00 00 00H]
            if nextByte != 0:
                found = False
            else:
                i += 20
    elif nextByte == 25:    # A11_CAPABILITIES_INFO_ACK
        xdr['msgType'] = 493
        print(xdr['display'],xdr['msgType'],'A11_CAPABILITIES_INFO_ACK')
        if xdr['sip'][len(xdr['sip'])-1] in pcfIP or xdr['dip'][len(xdr['dip'])-1] in pdsnIP:
            xdr['dir'] = '0'
            xdr['PCF_ip'] = xdr['sip'][len(xdr['sip'])-1]
            xdr['PDSN_ip'] = xdr['dip'][len(xdr['dip'])-1]
        else:
            xdr['dir'] = '1'
            xdr['PCF_ip'] = xdr['dip'][len(xdr['dip'])-1]
            xdr['PDSN_ip'] = xdr['sip'][len(xdr['sip'])-1]
        i += 1
        nextByte1,nextByte2,nextByte3 = struct.unpack('!3B',raw[i:i+3])   # Reserved = [00 00H]
        if nextByte1+nextByte2+nextByte3 != 0:
            found = False
        else:
            i += 3
            nextByte = struct.unpack('!I',raw[i:i+4])[0]  # Home Address = [00 00 00 00H]
            if nextByte != 0:
                found = False
            else:
                i += 16
    while i < rawLength and found == True:
        nextByte = struct.unpack('!B',raw[i:i+1])[0]
        i += 1
        if nextByte not in (32,38,39,134):
            found = False
            break
        else:
            if nextByte in (32,134):
                i += struct.unpack('!B',raw[i:i+1])[0]+1
            elif nextByte == 39:
                j = i+13
                i += struct.unpack('!B',raw[i:i+1])[0]+1
                length = struct.unpack('!B',raw[j:j+1])[0]
                j += 1
                number = struct.unpack(str(length)+'B',raw[j:j+length])
                n = ''.join(['{:02x}'.format(x) for x in number])
                xdr['imsi'] = n[0:1]+n[3:4]+n[2:3]+n[5:6]+n[4:5]+n[7:8]+n[6:7]+n[9:10]+n[8:9]+n[11:12]+n[10:11]+n[13:14]+n[12:13]+n[15:16]+n[14:15]
            else:
                i += 1
                i += struct.unpack('!H',raw[i:i+2])[0]+2
    cacheA11XDR(xdr)
    return

# A11
def outputA11XDR(xdr):
    global a11OutputFile,a11CPLatencyOutputFile
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'A11'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','','',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if a11OutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        a11OutputFileName = os.path.join(status.sdlDirectory,'LteCP_A11_Msg_'+b+'.tmp')
        a11OutputFile = open(a11OutputFileName,'w')
        if a11OutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(a11OutputFile)
    a11OutputFile.writelines(string)

    # CPLatency
    if xdr['msgType'] in [486,488,490,492]:
        temp = a11CPLatency.get((xdr['msgType'],xdr['imsi']),0)
        if temp != 0:
            temp.append(xdr['ts'])
        else:
            temp = [xdr['ts']]
            a11CPLatency[(xdr['msgType'],xdr['imsi'])] = temp
        return
    elif xdr['msgType'] in [487,489,491,493]:
        temp = a11CPLatency.get((a11Pair[xdr['msgType']][0],xdr['imsi']),0)
        if temp != 0:
            xdr['prcType'] = a11Pair[xdr['msgType']][1]
            if xdr['prcType'] == 2004 and xdr['dir'] == '0':
                xdr['prcType'] = 2005
            if xdr['Cause'] == a11Pair[xdr['msgType']][2]:
                xdr['SuccFlag'] = 0
            else:
                xdr['SuccFlag'] = 2
            xdr['Retrs'] = len(temp)
            if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
            ts = temp[0]
            for n in temp[1:]:
                if n[0] < ts[0]:
                    ts = n
                elif n[0] > ts[0]:
                    pass
                else:
                    if n[1] < ts[1]:
                        ts = n
            temp1 = ts[0]*1000000000+ts[1]
            temp2 = xdr['ts'][0]*1000000000+xdr['ts'][1]
            xdr['Latency'] = str((temp2 - temp1)//1000000)
            if(xdr['Latency'] == '0'):
                xdr['Latency'] = '1'
            xdr['ts'] = ts
            del a11CPLatency[(a11Pair[xdr['msgType']][0],xdr['imsi'])]
        else:
            del xdr
            return
    else:
        del xdr
        return
    xdr['msisdn'] = ''
    xdr['tid'] = ''
    xdr['tac'] = ''
    xdr['Timeout'] = ''
    xdr['APN_Id'] = ''
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Lac'])+'|'+str(xdr['Network'])+'|'+str(xdr['PCF_ip'])+'|'+str(xdr['PDSN_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'

    if a11CPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        a11CPLatencyOutputFileName = os.path.join(status.sdlDirectory,'LteRTI_A11_CPLatency_'+b+'.tmp')
        a11CPLatencyOutputFile = open(a11CPLatencyOutputFileName,'w')
        if a11CPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(a11CPLatencyOutputFile)
    a11CPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)

def cacheA11XDR(xdr):
    outputA11XDR(xdr)

def flushA11XDR():
    pass

pcfIP = []
pdsnIP = []

a11OutputFile = None
a11CPLatencyOutputFile = None
a11CPLatency = {}

# Type    dir msgNameUS                         msgNameCN           Notes
# 2001    0   A11_REGISTRATION_REQUEST          A11注册请求         A11_REGISTRATION_REQUEST(486)->A11_REGISTRATION_REPLY(487)
# 2002    1   A11_REGISTRATION_UPDATE           A11注册更新         A11_REGISTRATION_UPDATE(488)->A11_REGISTRATION_ACKNOWLEDGE(498)
# 2003    1   A11_SESSION_UPDATE                A11会话更新         A11_SESSION_UPDATE(490)->A11_SESSION_UPDATE_ACKNOWLEDGE(491)
# 2004    0   A11_CAPABILITIES_INFO(UNLINK)     A11能力信息(上行)   A11_CAPABILITIES_INFO(492)->A11_CAPABILITIES_INFO_ACK(493)
# 2005    1   A11_CAPABILITIES_INFO(DOWNLINK)   A11能力信息(下行)   A11_CAPABILITIES_INFO(492)->A11_CAPABILITIES_INFO_ACK(493)

a11Pair = {}
# 2001
a11Pair[487] = (486,2001,0)

# 2002
a11Pair[489] = (488,2002,0)

# 2003
a11Pair[491] = (490,2003,0)

# 2004/2005
a11Pair[493] = (492,2004,0)
