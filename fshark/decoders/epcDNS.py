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
import tcp
from collections import Counter

def getDNS(raw,pos):
    length = len(raw)
    i = pos
    j = i
    fields = []
    while i < length:
        fieldLength = struct.unpack('!1B',raw[i:i+1])[0]
        i += 1
        if i > j: j = i
        if fieldLength == 0:
            return '.'.join([x for x in fields]),j
        elif fieldLength == 0xC0:
            k = struct.unpack('!1B',raw[i:i+1])[0]
            i += 1
            if i > j: j = i
            i = k
        else:
            fieldString = struct.unpack('!'+str(fieldLength)+'s',raw[i:i+fieldLength])[0].decode('ascii')
            fields.append(fieldString)
            i += fieldLength
            if i > j: j = i
            
def decodeEPCDNS(xdr,raw,flush):
    xdr['display'] += ', DNS'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','4'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''
    xdr['ip'] = 0

    if(len(raw) <= 12):
        print("Error, DNS raw is less than 12 bytes.")
        return
    try:
        http = struct.unpack('!8s',raw[:8])[0].decode('ascii')
        if http == r'HTTP/1.1':
            return
    except Exception as err:
        #print('yyy ',err)
        pass
    finally:
        #print('Goodbye!')
        pass

    tID, flags, questions,answers, auth,add = struct.unpack('!6H',raw[:12])
    if questions > 2 or answers> 100 or auth > 100 or add > 100:
        print(xdr['display'], ' Malformed Packet: DNS')
        del xdr,raw
        return
    length = len(raw)

    msgType = flags>>15         # 0: DNS query,  1: DNS Response
    if flags>>15 == 0:
        xdr['msgType'] = 900
        xdr['dir'] = '0'
        xdr['intValue'] = (flags>>11)&15
    else:
        xdr['msgType'] = 901
        xdr['Cause'] = flags&15
        xdr['dir'] = '1'
        xdr['intValue'] = (flags>>11)&15
    pos = 12
    for m in range(questions):
        dnsName,pos = getDNS(raw,pos)
        fieldType = struct.unpack('!H',raw[pos:pos+2])[0]
        pos += 2
        if fieldType == 1:
            fieldClass = struct.unpack('!H',raw[pos:pos+2])[0]
            pos += 2
        elif fieldType == 35:
            fieldClass = struct.unpack('!H',raw[pos:pos+2])[0]
            pos += 2
        else:
            fieldClass = struct.unpack('!H',raw[pos:pos+2])[0]
            pos += 2
    if xdr['msgType'] == 900:
        xdr['strValue'] = dnsName
    xdr['questions'] = dnsName
    answerList = {}
    listOrder = []
    for m in range(answers):
        dnsName,pos= getDNS(raw,pos)
        answer = answerList.get(dnsName,0)
        if answer == 0:
            answer = []
            answerList[dnsName] = answer
            listOrder.append(dnsName)
        fieldType = struct.unpack('!H',raw[pos:pos+2])[0]
        pos += 2
        if fieldType == 1:
            fieldClass = struct.unpack('!H',raw[pos:pos+2])[0]
            pos += 2
            ttl = struct.unpack('!I',raw[pos:pos+4])[0]
            pos += 4
            dataLength = struct.unpack('!H',raw[pos:pos+2])[0]
            pos += 2
            temp = struct.unpack('!4s',raw[pos:pos+4])[0]
            pos += 4
            address = '.'.join([str(x) for x in temp])
            answer.append(address)
        elif fieldType == 5:
            fieldClass = struct.unpack('!H',raw[pos:pos+2])[0]
            pos += 2
            ttl = struct.unpack('!I',raw[pos:pos+4])[0]
            pos += 4
            dataLength = struct.unpack('!H',raw[pos:pos+2])[0]
            pos += 2
            cname,pos = getDNS(raw,pos)
            answer.append(cname)
    if xdr['msgType'] == 901:
        ansList = []
        for n in listOrder:
            answer = answerList[n]
            ansList.append(n+':'+','.join([x for x in answer]))
        xdr['strValue'] = ';'.join([x for x in ansList])
        xdr['answers'] = xdr['strValue']
        if len(xdr['strValue']) == 0:
            xdr['strValue'] = dnsName

    xdr['tID'] = tID

    mtype = ''
    m = regexIMS1.search(xdr['strValue'])
    if mtype == '':
        if m:
            mtype = 'ims'
            xdr['keyword4'] = 'SBC'

    m = regexIMS2.search(xdr['strValue'])
    if mtype == '':
        if m: 
            mtype = 'ims'
            xdr['keyword4'] = 'SBC'

    m = regexE164.search(xdr['strValue'])
    if mtype == '':
        if m: 
            mtype = 'ims'
            xdr['keyword4'] = 'SCSCF'

    m = regexLTE.search(xdr['strValue'])
    if mtype == '':
        if m: 
            mtype = 'epc'
            xdr['keyword4'] = 'MME'

    m = regexGPRS.search(xdr['strValue'])
    if mtype == '':
        if m: 
            mtype = 'epc'
            xdr['keyword4'] = 'SGSN'

    print(xdr['display'],mtype)
    if mtype == 'ims':
        outputIMSEPCDNSXDR(xdr)
    elif mtype == 'epc':
        outputLTEEPCDNSXDR(xdr)

    return

def outputLTEEPCDNSXDR(xdr):
    global lteEPCdnsOutputFile,lteEPCCPLatencyOutputFile
    
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'DNS'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    if(xdr['msgType'] == 900):
        xdr['strValue'] = 'EPC Query'
    else:
        xdr['strValue'] = 'EPC Answer'

    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','',xdr['keyword4'],'',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if lteEPCdnsOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        lteEPCdnsOutputFileName = os.path.join(status.sdlDirectory, 'LteCP_EPC_Msg_'+b+'.tmp')
        lteEPCdnsOutputFile = open(lteEPCdnsOutputFileName,'w')
        if lteEPCdnsOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(lteEPCdnsOutputFile)
    lteEPCdnsOutputFile.writelines(string)
    # CPLatency
    if xdr['msgType'] == 900:
        context = (xdr['sip'][len(xdr['sip'])-1],xdr['dip'][len(xdr['dip'])-1],xdr['sport'],xdr['tID'],xdr['questions'])
        temp = lteEPCdnsCPLatency.get(context,0)
        if temp != 0:
            temp.append(xdr)
            return
        else:
            temp = [xdr]
            lteEPCdnsCPLatency[context] = temp
            return
    
    temp = 0
    m = 0

    if xdr['msgType'] == 901:
        context = (xdr['dip'][len(xdr['dip'])-1],xdr['sip'][len(xdr['sip'])-1],xdr['dport'],xdr['tID'],xdr['questions'])
        temp = lteEPCdnsCPLatency.get(context,0)

    if temp == 0:
        del xdr
        return

    xdr['prcType'] = 2000               # maybe 999
    if xdr['Cause'] == 0:
        xdr['SuccFlag'] = 0
    else:
        xdr['SuccFlag'] = 2
    xdr['Retrs'] = len(temp)
    if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
    ts = temp[0]['ts']
    for n in temp[1:]:
        if n['ts'][0] < ts[0]:
            ts = n['ts']
        elif n['ts'][0] > ts[0]:
            pass
        else:
            if n['ts'][1] < ts[1]:
                ts = n['ts']
    temp1 = ts[0]*1000000000+ts[1]
    temp2 = xdr['ts'][0]*1000000000+xdr['ts'][1]
    xdr['Latency'] = str((temp2 - temp1)//1000000)
    if(xdr['Latency'] == '0'):
        xdr['Latency'] = '1'
    xdr['ts'] = ts
    del lteEPCdnsCPLatency[context]

    xdr['APN_Id'] = ''
    xdr['msisdn'] = ''
    xdr['Timeout'] = ''
    xdr['Req_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
    xdr['Ans_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
    xdr['name_servers'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['Network'])+'|'+str(xdr['Req_ip'])+'|'+str(xdr['Ans_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['questions']+'|'+xdr['answers']+'|'+str(xdr['name_servers'])+'\n'
    if lteEPCCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        lteEPCCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_EPC_CPLatency_'+b+'.tmp')
        lteEPCCPLatencyOutputFile = open(lteEPCCPLatencyOutputFileName,'w')
        if lteEPCCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(lteEPCCPLatencyOutputFile)
    lteEPCCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)
    return
def outputIMSEPCDNSXDR(xdr):
    global imsEPCdnsOutputFile,imsEPCCPLatencyOutputFile
    
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'DNS'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    if(xdr['msgType'] == 900):
        xdr['strValue'] = 'IMS Query'
    else:
        xdr['strValue'] = 'IMS Answer'

    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','',xdr['keyword4'],'',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if imsEPCdnsOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        imsEPCdnsOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_EPC_Msg_'+b+'.tmp')
        imsEPCdnsOutputFile = open(imsEPCdnsOutputFileName,'w')
        if imsEPCdnsOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(imsEPCdnsOutputFile)
    imsEPCdnsOutputFile.writelines(string)
    
    
    # CPLatency
    if xdr['msgType'] == 900:
        context = (xdr['sip'][len(xdr['sip'])-1],xdr['dip'][len(xdr['dip'])-1],xdr['sport'],xdr['tID'],xdr['questions'])
        temp = imsEPCdnsCPLatency.get(context,0)
        if temp != 0:
            temp.append(xdr)
            return
        else:
            temp = [xdr]
            imsEPCdnsCPLatency[context] = temp
            return
    
    temp = 0
    m = 0

    if xdr['msgType'] == 901:
        context = (xdr['dip'][len(xdr['dip'])-1],xdr['sip'][len(xdr['sip'])-1],xdr['dport'],xdr['tID'],xdr['questions'])
        temp = imsEPCdnsCPLatency.get(context,0)

    if temp == 0:
        del xdr
        return

    xdr['prcType'] = 2000               # maybe 999
    if xdr['Cause'] == 0:
        xdr['SuccFlag'] = 0
    else:
        xdr['SuccFlag'] = 2
    xdr['Retrs'] = len(temp)
    if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
    ts = temp[0]['ts']
    for n in temp[1:]:
        if n['ts'][0] < ts[0]:
            ts = n['ts']
        elif n['ts'][0] > ts[0]:
            pass
        else:
            if n['ts'][1] < ts[1]:
                ts = n['ts']
    temp1 = ts[0]*1000000000+ts[1]
    temp2 = xdr['ts'][0]*1000000000+xdr['ts'][1]
    xdr['Latency'] = str((temp2 - temp1)//1000000)
    if(xdr['Latency'] == '0'):
        xdr['Latency'] = '1'
    xdr['ts'] = ts
    del imsEPCdnsCPLatency[context]

    xdr['APN_Id'] = ''
    xdr['msisdn'] = ''
    xdr['Timeout'] = ''
    xdr['Req_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
    xdr['Ans_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
    xdr['name_servers'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['Network'])+'|'+str(xdr['Req_ip'])+'|'+str(xdr['Ans_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['questions']+'|'+xdr['answers']+'|'+str(xdr['name_servers'])+'\n'
    if imsEPCCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        imsEPCCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_EPC_CPLatency_'+b+'.tmp')
        imsEPCCPLatencyOutputFile = open(imsEPCCPLatencyOutputFileName,'w')
        if imsEPCCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(imsEPCCPLatencyOutputFile)
    imsEPCCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)
    return

def flushLTEEPCDNSXDR():
    global lteEPCCPLatencyOutputFile
    for n in lteEPCdnsCPLatency:
        xdr = lteEPCdnsCPLatency[n][0]
        xdr['prcType'] = 2000                                       # maybe 999
        xdr['SuccFlag'] = 1
        xdr['Retrs'] = len(lteEPCdnsCPLatency[n])
        if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
        xdr['Latency'] = ''
        xdr['msisdn'] = ''
        xdr['Timeout'] = ''
        xdr['Req_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
        xdr['Ans_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
        xdr['name_servers'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
        if xdr.get('answers',0) == 0: xdr['answers'] = r''
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['Network'])+'|'+str(xdr['Req_ip'])+'|'+str(xdr['Ans_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['questions']+'|'+xdr['answers']+'|'+str(xdr['name_servers'])+'\n'
        if lteEPCCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            lteEPCCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_EPC_CPLatency_'+b+'.tmp')
            lteEPCCPLatencyOutputFile = open(lteEPCCPLatencyOutputFileName,'w')
            if lteEPCCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(lteEPCCPLatencyOutputFile)
        lteEPCCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    lteEPCdnsCPLatency.clear()
    return
def flushIMSEPCDNSXDR():
    global imsEPCCPLatencyOutputFile
    for n in imsEPCdnsCPLatency:
        xdr = imsEPCdnsCPLatency[n][0]
        xdr['prcType'] = 2000                                       # maybe 999
        xdr['SuccFlag'] = 1
        xdr['Retrs'] = len(imsEPCdnsCPLatency[n])
        if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
        xdr['Latency'] = ''
        xdr['msisdn'] = ''
        xdr['Timeout'] = ''
        xdr['Req_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
        xdr['Ans_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
        xdr['name_servers'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
        if xdr.get('answers',0) == 0: xdr['answers'] = r''
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['Network'])+'|'+str(xdr['Req_ip'])+'|'+str(xdr['Ans_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['questions']+'|'+xdr['answers']+'|'+str(xdr['name_servers'])+'\n'
        if imsEPCCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            imsEPCCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_EPC_CPLatency_'+b+'.tmp')
            imsEPCCPLatencyOutputFile = open(imsEPCCPLatencyOutputFileName,'w')
            if imsEPCCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(imsEPCCPLatencyOutputFile)
        imsEPCCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    imsEPCdnsCPLatency.clear()
    return

lteEPCdnsOutputFile = None
imsEPCdnsOutputFile = None
lteEPCCPLatencyOutputFile = None
imsEPCCPLatencyOutputFile = None
lteEPCdnsCPLatency = {}
imsEPCdnsCPLatency = {}

epcIP = []
imsIP = []

ims1Format = r'\.ims\.\w+\.\w+$'
ims2Format = r'\.ims\.'
e164Format = r'\.e164\.arpa'
lteFormat = r'epc\.mnc\d{3}\.mcc\d{3}\.3gppnetwork\.org'
gprsFormat = r'mcc\d{3}\.gprs'

regexIMS1 = re.compile(ims1Format)
regexIMS2 = re.compile(ims2Format)
regexE164 = re.compile(e164Format)
regexLTE = re.compile(lteFormat)
regexGPRS = re.compile(gprsFormat)