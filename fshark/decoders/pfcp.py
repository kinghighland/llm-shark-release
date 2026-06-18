import sys
import os
import struct
import base64
import datetime
import time
import binascii
import pcap
from socket import inet_ntop, AF_INET6, inet_ntoa 
import status
from collections import Counter

def decodePFCP(xdr,raw,flush):
    global errorNum,maxSessionID
    if(len(raw)<8):
        print("Error, message length less than 8 bytes")
        return
    Flags, msgType, msgLength = struct.unpack("!BBH",raw[0:4])
    if(Flags & 1):
        xdr['SequenceNumber'] = struct.unpack("!I",b'\00'+raw[12:15])[0]
        pos = 16
    else:
        xdr['SequenceNumber'] = struct.unpack("!I",b'\00'+raw[4:7])[0]
        pos = 8

    xdr['display'] += ', PFCP'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','5'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''
    xdr['msgType'],xdr['dir'],pfcp_msg_type_name = pfcp_pdu.get(msgType,None)

    body_length = len(raw)
    while pos < body_length - 4:
        ie_type, ie_length = struct.unpack("!HH",raw[pos:pos+4])
        pos += 4
        if ie_type == 19:
            xdr['Cause'] = struct.unpack("!B",raw[pos:pos+1])[0]
        pos += ie_length

    if(xdr['msgType'] == None):
        print("Error", xdr['msgType'], "is not a valid value, should below 57")
        return
    print(xdr['display'],xdr['msgType'],pfcp_msg_type_name)
    xdr['sessionID'] = 0
    outputPFCPXDR(xdr)

def outputPFCPXDR(xdr):
    global pfcpOutputFile, pfcpCPLatencyOutputFile
    if xdr['imsi'] == '0': xdr['imsi'] = str(888880000000000+xdr['sessionID'])
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'N4'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr['SequenceNumber']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if pfcpOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        pfcpOutputFileName = os.path.join(status.sdlDirectory, 'NrCP_N4_Msg_'+b+'.tmp')
        pfcpOutputFile = open(pfcpOutputFileName,'w')
        if pfcpOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(pfcpOutputFile)
    pfcpOutputFile.writelines(string)

    # CPLatency
    if xdr['msgType'] in ('30300', '30302', '30304', '30306', '30308', '30311', '30313', '30315', '30317', '30319', '30321'):     # request msg
        temp = pfcpCPLatency.get((xdr['sip'][0],xdr['sport'],xdr['dip'][0],xdr['dport'],xdr['SequenceNumber']),0)               
        if temp != 0:
            temp.append(xdr['ts'])
        else:
            temp = [xdr['ts']]
            pfcpCPLatency[(xdr['sip'][0],xdr['sport'],xdr['dip'][0],xdr['dport'],xdr['SequenceNumber'])] = temp
    if xdr['msgType'] in ('30301', '30303', '30305', '30307', '30309', '30312', '30314', '30316', '30318', '30320'):
        temp = pfcpCPLatency.get((xdr['dip'][0],xdr['dport'],xdr['sip'][0],xdr['sport'],xdr['SequenceNumber']),0)
        if temp != 0:
            xdr['prcType'] = pfcpPair[xdr['msgType']][1]
            if xdr['Cause'] >= 1 and xdr['Cause'] <= 63:
                xdr['SuccFlag'] = 0
            elif(xdr['msgType'] == '30301'):                   # PFCP Heartbeat Response has not Cause IE, so a responding msg means the procedure is successful.
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
            del pfcpCPLatency[(xdr['dip'][0],xdr['dport'],xdr['sip'][0],xdr['sport'],xdr['SequenceNumber'])]
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
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+'|'+str(struct.unpack('!I',xdr['dip'][0][0:4])[0])+'|'+str(struct.unpack('!I',xdr['sip'][0][0:4])[0])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
    if pfcpCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        pfcpCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_N4_CPLatency_'+b+'.tmp')
        pfcpCPLatencyOutputFile = open(pfcpCPLatencyOutputFileName,'w')
        if pfcpCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(pfcpCPLatencyOutputFile)
    pfcpCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)

def cachePFCPXDR(xdr):
    pass

def flushPFCPXDR():
    pass

pfcpXDR = []

CPlatencyXDR = []

pagingList = {}
pathSwitchReqList = {}
maxSessionID = 0

pfcpOutputFile = None
pfcpCPLatencyOutputFile = None
pfcpCPLatency = {}

pfcp_pdu = {1:('30300','1','PFCP Heartbeat Request'), 2:('30301','0','PFCP Heartbeat Response'), 3:('30302','0','PFCP PFD Management Request'), 4:('30303','1','PFCP PFD Management Response'), 5:('30304','0','PFCP Association Setup Request'), 6:('30305','1','PFCP Association Setup Response'), 7:('30306','1','PFCP Association Update Request'), 8:('30307','0','PFCP Association Update Response'), 9:('30308','0','PFCP Association Release Request'), 10:('30309','1','PFCP Association Release Response'), 11:('30310','1','PFCP Version Not Supported Response'), 12:('30311','1','PFCP Node Report Request'), 13:('30312','0','PFCP Node Report Response'), 14:('30313','1','PFCP Session Set Deletion Request'), 15:('30314','0','PFCP Session Set Deletion Response'), 50:('30315','0','PFCP Session Establishment Request'), 51:('30316','1','PFCP Session Establishment Response'), 52:('30317','0','PFCP Session Modification Request'), 53:('30318','1','PFCP Session Modification Response'), 54:('30319','0','PFCP Session Deletion Request'), 55:('30320','1','PFCP Session Deletion Response'), 56:('30321','1','PFCP Session Report Request'), 57:('30322','0','PFCP Session Report Response'),}

# Type    dir  msgNameUS                           msgNameCN          Notes                                                                    Category    XDR
# 6010    0    PFCP Heartbeat Request              PFCP心跳           PFCP Heartbeat Request(30300)->PFCP Heartbeat Response(30301)                          N4          NrRTI_N4_CPLatency
# 6011    1    PFCP PFD Management Request         PFCP PFD管理请求    PFCP PFD Management Request(30302)->PFCP PFD Management Response(30303)               N4          NrRTI_N4_CPLatency
# 6012    0    PFCP Association Setup Request      PFCP关联设置请求    PFCP Association Setup Request(30304)->PFCP Association Setup Response(30305)          N4          NrRTI_N4_CPLatency
# 6013    0    PFCP Association Update Request     PFCP关联更新请求    PFCP Association Update Request(30306)->PFCP Association Update Response(30307)        N4          NrRTI_N4_CPLatency
# 6014    1    PFCP Association Release Request    PFCP关联释放请求    PFCP Association Release Request(30308)->PFCP Association Release Response(30309)      N4          NrRTI_N4_CPLatency
# 6015    0    PFCP Node Report Request            PFCP节点报告请求    PFCP Node Report Request(30311)->PFCP Node Report Response(30312)                      N4          NrRTI_N4_CPLatency
# 6016    0    PFCP Session Set Deletion Request   PFCP会话释放请求    PFCP Session Set Deletion Request(30313)->PFCP Session Set Deletion Response(30314)    N4          NrRTI_N4_CPLatency
# 6017    1    PFCP Session Establishment Request  PFCP会话建立请求    PFCP Session Establishment Request(30315)->PFCP Session Establishment Response(30316)  N4          NrRTI_N4_CPLatency
# 6018    1    PFCP Session Modification Request   PFCP会话更新请求    PFCP Session Modification Request(30317)->PFCP Session Modification Response(30318)    N4          NrRTI_N4_CPLatency
# 6019    1    PFCP Session Deletion Request       PFCP会话释放请求    PFCP Session Deletion Request(30319)->PFCP Session Deletion Response(30320)            N4          NrRTI_N4_CPLatency
# 6020    0    PFCP Session Report Request         PFCP会话报告请求    PFCP Session Report Request(30321)->PFCP Session Report Response(30322)                N4          NrRTI_N4_CPLatency


pfcpPair = {}
pfcpPair['30301'] = ('30300', '6010', 0)
pfcpPair['30303'] = ('30302', '6011', 0)
pfcpPair['30305'] = ('30304', '6012', 0)
pfcpPair['30307'] = ('30306', '6013', 0)
pfcpPair['30309'] = ('30308', '6014', 0)
pfcpPair['30312'] = ('30311', '6015', 0)
pfcpPair['30314'] = ('30313', '6016', 0)
pfcpPair['30316'] = ('30315', '6017', 0)
pfcpPair['30318'] = ('30317', '6018', 0)
pfcpPair['30320'] = ('30319', '6019', 0)
pfcpPair['30322'] = ('30321', '6020', 0)
