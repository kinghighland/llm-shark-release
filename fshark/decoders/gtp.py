import sys
import os
import struct
import base64
import datetime
import time
import binascii
import pcap
import re
import ip
import status
import tcp
import gtpv2
from socket import inet_ntop, AF_INET6, inet_ntoa
from collections import Counter

def decodeGTP(xdr,raw,flush):
    global maxSessionID
    xdr['display'] += ', GTP'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','3'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''
    xdr['ip'] = 0
    xdr['gtp'] = True

    pos = 0
    flags,msgType,Length,teid = struct.unpack('!BBHI',raw[pos:pos+8])
    if (flags>>5) == 2:
        gtpv2.decodeGTPV2(xdr,raw,False)
        return

    E = (flags >> 2) & 1
    S = (flags >> 1) & 1
    PN = flags & 1
    pos += 8       # GTP fixed header length: Flags, MsgType, TEID

    # 扩展部分以4个字节为一组占用空间。其中S占前两个字节，第三个字节是PN，左右一个字节是Next Extension Header Type
    if(S == 1 or PN == 1 or E == 1):
        pos += 4
    if(E == 1):    # 仅仅GPRS使用
        nextExtenstionHeaderType = raw[pos - 1]
        while(nextExtenstionHeaderType != 0):
            extenstinLength = raw[pos] * 4
            pos += extenstinLength
            nextExtenstionHeaderType = raw[pos - 1]

    if msgType == 255:
        ipType = struct.unpack('!B',raw[pos:pos+1])[0]
        if (ipType>>4) == 4:
            ip.decodeIPv4(xdr,raw[pos:])
        elif (ipType>>4) == 6:
            ip.decodeIPv6(xdr,raw[pos:])
        else:
            print('Found unknown GTP Data Type', (ipType>>4))
        del xdr,raw
        return
    elif msgType == 16:
        print(xdr['display'],'CREATE_PDP_CONTEXT_REQUEST')
        xdr['msgType'] = 371
        xdr['dir'] = '0'
        xdr['SGSN_ip'] = xdr['sip'][0]
        xdr['GGSN_ip'] = xdr['dip'][0]
        if xdr['sip'][0] not in sgsnIP: sgsnIP.append(xdr['sip'][0])
        while pos < len(raw)-2:
            ieType = struct.unpack('!B',raw[pos:pos+1])[0]
            if ieType in (1,8,11,13,14,15,19,20,21,23,24,29):
                if ieType == 1:
                    xdr['Cause'] = struct.unpack('!B',raw[pos+1:pos+2])[0]
                pos += 2
            elif ieType in (25,26,27,28):
                pos += 3
            elif ieType == 12:
                pos += 4
            elif ieType in (4,5,16,17,127):
                if ieType == 17:
                    xdr['gtpTEID'] = struct.unpack('!I',raw[pos+1:pos+5])[0]
                pos += 5
            elif ieType == 18:
                pos += 6
            elif ieType == 3:
                pos += 7
            elif ieType == 2:
                imsi = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+9]])
                xdr['imsi'] = imsi[0:-1]
                pos += 9
            elif ieType == 22:
                pos += 10
            elif ieType == 9:
                pos += 29
            else:
                ieLength = struct.unpack('!H',raw[pos+1:pos+3])[0]
                if ieType == 0x85:
                    xdr['gtpIP'] = struct.unpack('!I',raw[pos+3:pos+7])[0]
                pos += 3 + ieLength
    elif msgType == 17:
        print(xdr['display'],'CREATE_PDP_CONTEXT_RESPONSE')
        xdr['msgType'] = 372
        xdr['dir'] = '1'
        xdr['SGSN_ip'] = xdr['dip'][0]
        xdr['GGSN_ip'] = xdr['sip'][0]
        if xdr['dip'][0] not in sgsnIP: sgsnIP.append(xdr['dip'][0])
        ieType,Cause = struct.unpack('!2B',raw[pos:pos+2])
        if ieType == 1:
            xdr['Cause'] = Cause
    elif msgType == 18:
        print(xdr['display'],'UPDATE_PDP_CONTEXT_REQUEST')
        xdr['msgType'] = 378
        xdr['dir'] = '0'
        xdr['SGSN_ip'] = xdr['sip'][0]
        xdr['GGSN_ip'] = xdr['dip'][0]
        if xdr['sip'][0] not in sgsnIP: sgsnIP.append(xdr['sip'][0])
        while pos < len(raw)-2:
            ieType = struct.unpack('!B',raw[pos:pos+1])[0]
            if ieType in (1,8,11,13,14,15,19,20,21,23,24,29):
                if ieType == 1:
                    xdr['Cause'] = struct.unpack('!B',raw[pos+1:pos+2])[0]
                pos += 2
            elif ieType in (25,26,27,28):
                pos += 3
            elif ieType == 12:
                pos += 4
            elif ieType in (4,5,16,17,127):
                if ieType == 17:
                    xdr['gtpTEID'] = struct.unpack('!I',raw[pos+1:pos+5])[0]
                pos += 5
            elif ieType == 18:
                pos += 6
            elif ieType == 3:
                pos += 7
            elif ieType == 2:
                imsi = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+9]])
                xdr['imsi'] = imsi[0:-1]
                pos += 9
            elif ieType == 22:
                pos += 10
            elif ieType == 9:
                pos += 29
            else:
                ieLength = struct.unpack('!H',raw[pos+1:pos+3])[0]
                if ieType == 0x85:
                    xdr['gtpIP'] = struct.unpack('!I',raw[pos+3:pos+7])[0]
                pos += 3 + ieLength
    elif msgType == 19:
        print(xdr['display'],'UPDATE_PDP_CONTEXT_RESPONSE')
        xdr['msgType'] = 379
        xdr['dir'] = '1'
        xdr['SGSN_ip'] = xdr['dip'][0]
        xdr['GGSN_ip'] = xdr['sip'][0]
        if xdr['dip'][0] not in sgsnIP: sgsnIP.append(xdr['dip'][0])
        ieType,Cause = struct.unpack('!2B',raw[pos:pos+2])
        if ieType == 1:
            xdr['Cause'] = Cause
    elif msgType == 20:
        print(xdr['display'],'DELETE_PDP_CONTEXT_REQUEST')
        xdr['msgType'] = 373
        if xdr['sip'][0] in sgsnIP:
            xdr['dir'] = '0'
            xdr['SGSN_ip'] = xdr['sip'][0]
            xdr['GGSN_ip'] = xdr['dip'][0]
        if xdr['dip'][0] in sgsnIP:
            xdr['dir'] = '1'
            xdr['SGSN_ip'] = xdr['dip'][0]
            xdr['GGSN_ip'] = xdr['sip'][0]
        if xdr['dir'] == 2:
            xdr['dir'] = '0'
            xdr['SGSN_ip'] = xdr['sip'][0]
            xdr['GGSN_ip'] = xdr['dip'][0]
        ieType,Cause = struct.unpack('!2B',raw[pos:pos+2])
        if ieType == 1:
            xdr['Cause'] = Cause
    elif msgType == 21:
        print(xdr['display'],'DELETE_PDP_CONTEXT_RESPONSE')
        xdr['msgType'] = 374
        if xdr['sip'][0] in sgsnIP:
            xdr['dir'] = '0'
            xdr['SGSN_ip'] = xdr['sip'][0]
            xdr['GGSN_ip'] = xdr['dip'][0]
        if xdr['dip'][0] in sgsnIP:
            xdr['dir'] = '1'
            xdr['SGSN_ip'] = xdr['dip'][0]
            xdr['GGSN_ip'] = xdr['sip'][0]
        if xdr['dir'] == 2:
            xdr['dir'] = '1'
            xdr['SGSN_ip'] = xdr['dip'][0]
            xdr['GGSN_ip'] = xdr['sip'][0]
        ieType,Cause = struct.unpack('!2B',raw[pos:pos+2])
        if ieType == 1:
            xdr['Cause'] = Cause
    elif msgType == 50:
        print(xdr['display'],'SGSN_CONTEXT_REQUEST')
        xdr['msgType'] = 376
        xdr['dir'] = '0'
        xdr['SGSN_ip'] = xdr['sip'][0]
        xdr['GGSN_ip'] = xdr['dip'][0]
        if xdr['sip'][0] not in sgsnIP: sgsnIP.append(xdr['sip'][0])
        if xdr['dip'][0] not in sgsnIP: sgsnIP.append(xdr['dip'][0])
        while pos < len(raw)-2:
            ieType = struct.unpack('!B',raw[pos:pos+1])[0]
            if ieType in (1,8,11,13,14,15,19,20,21,23,24,29):
                if ieType == 1:
                    xdr['Cause'] = struct.unpack('!B',raw[pos+1:pos+2])[0]
                pos += 2
            elif ieType in (25,26,27,28):
                pos += 3
            elif ieType == 12:
                pos += 4
            elif ieType in (4,5,16,17,127):
                if ieType == 17:
                    xdr['gtpTEID'] = struct.unpack('!I',raw[pos+1:pos+5])[0]
                pos += 5
            elif ieType == 18:
                pos += 6
            elif ieType == 3:
                pos += 7
            elif ieType == 2:
                imsi = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+9]])
                xdr['imsi'] = imsi[0:-1]
                pos += 9
            elif ieType == 22:
                pos += 10
            elif ieType == 9:
                pos += 29
            else:
                ieLength = struct.unpack('!H',raw[pos+1:pos+3])[0]
                if ieType == 0x85:
                    xdr['gtpIP'] = struct.unpack('!I',raw[pos+3:pos+7])[0]
                pos += 3 + ieLength
    elif msgType == 51:
        print(xdr['display'],'SGSN_CONTEXT_RESPONSE')
        xdr['msgType'] = 377
        xdr['dir'] = '1'
        xdr['SGSN_ip'] = xdr['dip'][0]
        xdr['GGSN_ip'] = xdr['sip'][0]
        if xdr['sip'][0] not in sgsnIP: sgsnIP.append(xdr['sip'][0])
        if xdr['dip'][0] not in sgsnIP: sgsnIP.append(xdr['dip'][0])
        while pos < len(raw)-2:
            ieType = struct.unpack('!B',raw[pos:pos+1])[0]
            if ieType in (1,8,11,13,14,15,19,20,21,23,24,29):
                if ieType == 1:
                    xdr['Cause'] = struct.unpack('!B',raw[pos+1:pos+2])[0]
                pos += 2
            elif ieType in (25,26,27,28):
                pos += 3
            elif ieType == 12:
                pos += 4
            elif ieType in (4,5,16,17,127):
                if ieType == 17:
                    xdr['gtpTEID'] = struct.unpack('!I',raw[pos+1:pos+5])[0]
                pos += 5
            elif ieType == 18:
                pos += 6
            elif ieType == 3:
                pos += 7
            elif ieType == 2:
                imsi = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+9]])
                xdr['imsi'] = imsi[0:-1]
                pos += 9
            elif ieType == 22:
                pos += 10
            elif ieType == 9:
                pos += 29
            else:
                ieLength = struct.unpack('!H',raw[pos+1:pos+3])[0]
                if ieType == 0x85:
                    xdr['gtpIP'] = struct.unpack('!I',raw[pos+3:pos+7])[0]
                pos += 3 + ieLength
    elif msgType == 52:
        print(xdr['display'],'SGSN_CONTEXT_ACK')
        xdr['msgType'] = 375
        xdr['dir'] = '0'
        xdr['SGSN_ip'] = xdr['sip'][0]
        xdr['GGSN_ip'] = xdr['dip'][0]
        if xdr['sip'][0] not in sgsnIP: sgsnIP.append(xdr['sip'][0])
        if xdr['dip'][0] not in sgsnIP: sgsnIP.append(xdr['dip'][0])
        ieType,Cause = struct.unpack('!2B',raw[pos:pos+2])
        if ieType == 1:
            xdr['Cause'] = Cause
    else:
        print(xdr['display'],msgType)
        return
    
    if xdr['teid'] == 0:
        maxSessionID += 1
        sessionID = maxSessionID
        teidSessionID[(xdr.get('gtpTEID',0),xdr.get('gtpIP',0))] = sessionID
        sequenceSessionID[((struct.unpack('!I',xdr['dip'][0])[0]),xdr['sequence'])] = sessionID
        sequenceSessionID[((struct.unpack('!I',xdr['sip'][0])[0]),xdr['sequence'])] = sessionID
    else:
        sessionID = teidSessionID.get((xdr.get('teid',0),struct.unpack('!I',xdr['dip'][0])[0]),0)
        if sessionID == 0:
            sessionID = sequenceSessionID.get(((struct.unpack('!I',xdr['dip'][0])[0]),xdr['sequence']),0)
            if sessionID == 0:
                sessionID = sequenceSessionID.get(((struct.unpack('!I',xdr['sip'][0])[0]),xdr['sequence']),0)                
                maxSessionID += 1
                sessionID = maxSessionID
                teidSessionID[(xdr.get('teid',0),struct.unpack('!I',xdr['dip'][0])[0])] = sessionID
                sequenceSessionID[((struct.unpack('!I',xdr['dip'][0])[0]),xdr['sequence'])] = sessionID
                sequenceSessionID[((struct.unpack('!I',xdr['sip'][0])[0]),xdr['sequence'])] = sessionID
        else:
            if xdr.get('gtpTEID',0) != 0 and xdr.get('gtpIP',0) != 0:
                teidSessionID[(xdr.get('gtpTEID',0),xdr.get('gtpIP',0))] = sessionID
                sequenceSessionID[((struct.unpack('!I',xdr['dip'][0])[0]),xdr['sequence'])] = sessionID
                sequenceSessionID[((struct.unpack('!I',xdr['sip'][0])[0]),xdr['sequence'])] = sessionID
    xdr['sessionID'] = sessionID
    if xdr.get('imsi','0') != '0':
        sessionIDIMSI[sessionID] = xdr['imsi']
    else:
        xdr['imsi'] = sessionIDIMSI.get(sessionID,'0')
    cacheGNGPXDR(xdr)
    return

def outputGNGPXDR(xdr):
    global gngpOutputFile,gngpCPLatencyOutputFile

    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    
    # generate xdr for web
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'GnGp'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','','',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))


    if gngpOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        gngpOutputFileName = os.path.join(status.sdlDirectory, 'LteCP_GnGp_Msg_'+b+'.tmp')
        gngpOutputFile = open(gngpOutputFileName,'w')
        if gngpOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(gngpOutputFile)
    gngpOutputFile.writelines(string)
    return
def cacheGNGPXDR(xdr):
    imsi = xdr.get('imsi','0')
    if imsi != '0':
        for i in range(len(gngpXDR)-1,-1,-1):
            if gngpXDR[i]['sessionID'] == xdr['sessionID']:
                gngpXDR[i]['imsi'] = xdr['imsi']
                outputGNGPXDR(gngpXDR[i])
                gngpXDR.remove(gngpXDR[i])
        outputGNGPXDR(xdr)
    else:
        gngpXDR.append(xdr)
    cacheGNGPCPlatency(xdr)
    return
def cacheGNGPCPlatency(xdr):
    global gngpCPLatencyXDR,gngpCPLatencyOutputFile
    if xdr['msgType'] in (371,378,373,376):
        temp = gngpCPLatency.get((xdr['sessionID'],xdr['msgType']),0)
        if temp == 0:
            gngpCPLatency[(xdr['sessionID'],xdr['msgType'])] = [xdr]
        else:
            gngpCPLatency[(xdr['sessionID'],xdr['msgType'])].append(xdr)
    outputXDRs = []
    if xdr['msgType'] in gngpPair.keys():
        msgType = gngpPair[xdr['msgType']]
        tempxdr = {}
        temp = gngpCPLatency.get((xdr['sessionID'],msgType[0]),0)
        if temp != 0:
            tempxdr['prcType'] = msgType[1]
            tempxdr['SuccFlag'] = msgType[2]
            tempxdr['Retrs'] = len(temp)
            if tempxdr['Retrs'] > 0: tempxdr['Retrs'] -= 1
            ts = temp[0]['ts']
            for m in temp[1:]:
                if m['ts'][0] < ts[0]:
                    ts = m['ts']
                elif m['ts'][0] > ts[0]:
                    pass
                else:
                    if m['ts'][1] < ts[1]:
                        ts = m['ts']
            temp1 = ts[0]*1000000000+ts[1]
            temp2 = xdr['ts'][0]*1000000000+xdr['ts'][1]
            tempxdr['Latency'] = str((temp2 - temp1)//1000000)
            if(tempxdr['Latency'] == '0'):
                tempxdr['Latency'] = '1'
            tempxdr['ts'] = ts
            del gngpCPLatency[(xdr['sessionID'],msgType[0])]
            tempxdr['msisdn'] = ''
            tempxdr['tid'] = ''
            tempxdr['tac'] = ''
            tempxdr['Timeout'] = ''
            tempxdr['Cause'] = xdr['Cause']
            tempxdr['pt_tsn'] = (tempxdr['ts'][0]-time.timezone) % 86400 // 3600
            tempxdr['cgi'] = xdr['cgi']
            tempxdr['Network'] = xdr['Network']
            tempxdr['SGSN_ip'] = struct.unpack('!I',xdr['SGSN_ip'])[0]
            tempxdr['GGSN_ip'] = struct.unpack('!I',xdr['GGSN_ip'])[0]
            tempxdr['sessionID'] = xdr['sessionID']
            imsi = sessionIDIMSI.get(xdr['sessionID'],'0')
            tempxdr['imsi'] = '0'
            if imsi != '0':
                tempxdr['imsi'] = imsi
            if xdr['imsi'] == '0':
                tempxdr['imsi'] = xdr['imsi']
            if tempxdr['imsi'] == '0':
                gngpCPlatencyXDR.append(tempxdr)
            else:
                outputXDRs.append(tempxdr)
    for xdr in outputXDRs:
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['SGSN_ip'])+'|'+str(xdr['GGSN_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
        if gngpCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            gngpCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_GnGp_CPLatency_'+b+'.tmp')
            gngpCPLatencyOutputFile = open(gngpCPLatencyOutputFileName,'w')
            if gngpCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(gngpCPLatencyOutputFile)
        gngpCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    return
def flushGNGPXDR():
    global gngpCPLatencyXDR,gngpCPLatencyOutputFile
    for n in gngpXDR:
        if n['imsi'] == '0':
            n['imsi'] = sessionIDIMSI.get(n['sessionID'],'0')
        outputGNGPXDR(n)
    gngpXDR.clear()

    for n in gngpCPlatencyXDR:
        if n['imsi'] == '0':
            n['imsi'] = sessionIDIMSI.get(n['sessionID'],'0')
    for xdr in gngpCPLatency:
        tempxdr = {}
        tempxdr['prcType'] = gngpPair1[xdr['msgType']]
        tempxdr['SuccFlag'] = 1
        tempxdr['Retrs'] = len(gngpCPLatency[xdr])
        if tempxdr['Retrs'] > 0: tempxdr['Retrs'] -= 1
        ts = gngpCPLatency[xdr][0]['ts']
        for m in gngpCPLatency[xdr][1:]:
            if m['ts'][0] < ts[0]:
                ts = m['ts']
            elif m['ts'][0] > ts[0]:
                pass
            else:
                if m['ts'][1] < ts[1]:
                    ts = m['ts']
        tempxdr['Latency'] = 0
        tempxdr['ts'] = ts
        tempxdr['msisdn'] = ''
        tempxdr['tid'] = ''
        tempxdr['tac'] = ''
        tempxdr['Timeout'] = ''
        tempxdr['Cause'] = xdr['Cause']
        tempxdr['pt_tsn'] = (tempxdr['ts'][0]-time.timezone) % 86400 // 3600
        tempxdr['cgi'] = xdr['cgi']
        tempxdr['Network'] = xdr['Network']
        tempxdr['SGSN_ip'] = struct.unpack('!I',xdr['SGSN_ip'])[0]
        tempxdr['GGSN_ip'] = struct.unpack('!I',xdr['GGSN_ip'])[0]
        tempxdr['sessionID'] = xdr['sessionID']
        # imsi = sessionIMSI.get(xdr['sessionID'],'0')
        tempxdr['imsi'] = '0'
        # if imsi != '0':
        #     tempxdr['imsi'] = imsi
        if xdr['imsi'] == '0':
            tempxdr['imsi'] = xdr['imsi']
        gngpCPlatencyXDR.append(tempxdr)
    for xdr in gngpCPlatencyXDR:
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['SGSN_ip'])+'|'+str(xdr['GGSN_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
        if gngpCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            gngpCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_GnGp_CPLatency_'+b+'.tmp')
            gngpCPLatencyOutputFile = open(gngpCPLatencyOutputFileName,'w')
            if gngpCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(gngpCPLatencyOutputFile)
        gngpCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    gngpCPlatencyXDR.clear()
    gngpCPLatency.clear()
    return

sgsnIP = []

gngpXDR = []

gngpOutputFile = None
gngpCPLatencyOutputFile = None

gngpCPLatency = {}
gngpCPlatencyXDR = []

# Type	dir	msgNameUS	    msgNameCN	        Notes
# 1600	0	CREATE_PDP	    创建PDP上下文流程	CREATE_PDP_CONTEXT_REQUEST(371)->CREATE_PDP_CONTEXT_RESPONSE(372)
# 1601	0	UPDATE_PDP	    更新PDP上下文流程	UPDATE_PDP_CONTEXT_REQUEST(378)->UPDATE_PDP_CONTEXT_RESPONSE(379)
# 1602	0	DELETE_PDP	    删除PDP上下文流程	DELETE_PDP_CONTEXT_REQUEST(373)->DELETE_PDP_CONTEXT_RESPONSE(374)
# 1603	0	SGSN_CONTEXT	SGSN上下文请求流程	SGSN_CONTEXT_REQUEST(376)->SGSN_CONTEXT_RESPONSE(377)

gngpPair = {}
# 1600
gngpPair[372] = (371,1600,0)
# 1601
gngpPair[379] = (378,1601,0)
# 1602
gngpPair[374] = (373,1602,0)
# 1603
gngpPair[377] = (376,1603,0)

gngpPair1 = {}
gngpPair1[371] = 1600
gngpPair1[378] = 1601
gngpPair1[373] = 1602
gngpPair1[376] = 1603


maxSessionID = 0
teidSessionID = {}
sessionIDIMSI = {}
sequenceSessionID = {}
