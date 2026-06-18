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

n26_session = {}

def getByGTPV2Code(raw,list,xdr):
    if list in (None,[]):
        print('list is empty')
        return
    out = {}
    pos = 0
    lengthRAW = len(raw)
    while pos < lengthRAW-4 and len(list) != 0:
        ieType,ieLength = struct.unpack('!BH',raw[pos:pos+3])
        if ieType in list:
            if ieType == 1:                                                   # IMSI
                string = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+4:pos+4+ieLength]])
                if string[-1] == 'F':
                    imsi = string[:-1]
                else:
                    imsi = string
                out[ieType]=imsi
            elif ieType == 2:                                                 # Cause
                cause = struct.unpack('!B',raw[pos+4:pos+5])[0]
                out[ieType]=cause
            elif ieType == 51:                                                # STN-SR
                type,length,cr,flag = struct.unpack('!BHBB',raw[pos:pos+5])
                if flag == 145:
                    string = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+5:pos+5+length-1]])
                    stn_sr = 0
                    if string[-1] == 'F':
                        stn_sr = string[:-1]
                    else:
                        stn_sr = string
                    if stn_sr != 0:
                        out[ieType]= stn_sr
            elif ieType == 76:                                                # MSISDN
                string = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+4:pos+4+ieLength]])
                if string[-1] == 'F':
                    msisdn = string[:-1]
                else:
                    msisdn = string
                out[ieType]=msisdn
            elif ieType == 86:                                                # ecgi
                nextByte = struct.unpack('!B',raw[pos+4:pos+5])[0]
                len1 = (nextByte&1)*7 + ((nextByte>>1)&1)*7 + ((nextByte>>2)&1)*7 + ((nextByte>>3)&1)*5 + 4
                cgi = struct.unpack('!I',raw[pos+4+len1:pos+4+len1+4])[0]
                out[ieType]=cgi
            elif ieType == 82:                                                # RAT Type
                nextByte = struct.unpack('!B',raw[pos+4:pos+5])[0]
                out[ieType] = nextByte
            elif ieType == 87:                                                # TEID S11 and S5/S8
                interfaceType = struct.unpack('!B',raw[pos+4:pos+5])[0]
                if interfaceType in (0x87,0x8a,0x8b):
                    teidGREKey,IPv4Addr = struct.unpack('!I4s',raw[pos+5:pos+13])
                    tempTEID = {'interfaceType':interfaceType,'TEIDKey':teidGREKey,'IPv4Addr':IPv4Addr}
                    if out.get(ieType,None) == None:
                        temp = []
                        temp.append(tempTEID)
                        out[ieType]=temp
                    else:
                        out[ieType].append(tempTEID)
            elif ieType == 71:                                                # APN
                string = struct.unpack('!'+str(ieLength)+'s',raw[pos+4:pos+4+ieLength])[0]
                i = pos+4
                fieldList = []
                while i < pos+4+ieLength:
                    fieldLength = raw[i]
                    fieldList.append(raw[i+1:i+1+fieldLength].decode())
                    i += fieldLength + 1
                out[ieType]='.'.join([x for x in fieldList])
            elif ieType == 73:                                                # EPS Bearer ID
                EBI = struct.unpack('!B',raw[pos+4:pos+4+ieLength])[0]
                xdr.setdefault('ebi',[]).append(EBI)
            elif ieType == 78:                                                # PCO P-CSCF IPv4 Address
                i = pos+5
                ip = 0
                while i < pos+4+ieLength:
                    pcID,pcLength = struct.unpack('!HB',raw[i:i+3])
                    if pcID ==  12:
                        ip = struct.unpack('!I',raw[i+3:i+7])[0]
                        break
                    i += 3 + pcLength
                out[ieType]=ip
            elif ieType == 79:                                                # PDN Address
                pdnType = struct.unpack('!B',raw[pos+4:pos+5])[0] & 7
                if pdnType == 1:
                    pdnAddress = struct.unpack('!I',raw[pos+5:pos+9])[0]
                else:
                    pdnAddress = 0
                    print('GTPv2 Found IPv6 PDN Type')
                state = {'pdnType':pdnType,'pdnAddress':pdnAddress}
                out[ieType]=state
            elif ieType == 93:                                                # Bearer Context, include GTP-U IP/TEID, EBI
                i = pos+4
                s1uTEID = 0
                while i < pos+4+ieLength:
                    pcID,pcLength = struct.unpack('!BH',raw[i:i+3])
                    if pcID ==  87:
                        interfaceType = struct.unpack('!B',raw[i+4:i+5])[0]
                        if interfaceType == 0x81:
                            teidKey = struct.unpack('!I',raw[i+5:i+9])[0]
                            IPv4Address = struct.unpack('!4s',raw[i+9:i+13])[0]
                            s1uTEID = {'interfaceType':interfaceType,'teidKey':teidKey,'IPv4Address':IPv4Address}
                            break
                    elif pcID == 73:                                                # EPS Bearer ID
                        EBI = struct.unpack('!B',raw[i+4:i+5])[0]
                        xdr.setdefault('ebi',[]).append(EBI)
                    i += 4 + pcLength
                out[ieType]=s1uTEID
            else:
                print('ieType',ieType,' unknown Diameter IE Type')
            #list.remove(ieType)                                              # IE is not unqic, for example: Bearer Context(93)
        pos += 4 + ieLength
    return out

def decodeGTPV2(xdr,raw,flush):
    xdr['display'] += ', GTPv2'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','4'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''
    xdr['ip'] = 0
    xdr['ebi'] = []

    i = 0
    flag,msgType,msgLength = struct.unpack('!2BH',raw[i:i+4])
    i += 4
    if msgType not in list(range(25,38))+list(range(64,71))+list(range(95,101))+list(range(128,142))+list(range(162,166))+[170,171]+[176,177]:
        print(xdr['display'],'id =',xdr['id'], 'msgType =',msgType)
        del xdr
        return
    if ((flag >> 3) & 1) == 1:
        xdr['teid'] = struct.unpack('!I',raw[i:i+4])[0]
        i += 4
    xdr['seq'] = struct.unpack('!I',raw[i:i+4])[0]>>8
    i += 4

    xdr['msgType'] = gtpv2Dict.get(msgType,0)
    # S11
    if xdr['msgType'] == 303:
        print(xdr['display'],xdr['msgType'],'Bearer Resource Command')
        xdr['s11Type'] = 0                                              # 0: request, 1: response
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 304:
        print(xdr['display'],xdr['msgType'],'Bearer Resource Failure Indication')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 305:
        print(xdr['display'],xdr['msgType'],'Create Bearer Request')
        xdr['s11Type'] = 0
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 306:
        print(xdr['display'],xdr['msgType'],'Create Bearer Response')
        xdr['s11Type'] = 1
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 307:
        print(xdr['display'],xdr['msgType'],'Create Session Request')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[1,76,86,87,87,71,73,93],xdr)
        xdr['imsi'] = ie.get(1,'0')
        xdr['misdn'] = ie.get(76,'0')
        if xdr['imsi'] != '0' and xdr['misdn'] != '0':
            status.msisdnIMSI[xdr['misdn']] = xdr['imsi']
            status.imsiMSISDN[xdr['imsi']] = xdr['misdn']
        xdr['cgi'] = ie.get(86,'0')
        teidList = ie.get(87,0)
        if teidList != 0:
            for n in teidList:
                if n.get('interfaceType',0) == 0x8a:
                    xdr['TEIDKey'] = n.get('TEIDKey',0)
                    xdr['IPv4Addr'] = n.get('IPv4Addr',0)
            xdr['apn'] = ie.get(71,0)
            state = {'imsi':xdr['imsi'],'msisdn':xdr['misdn'],'apn':xdr['apn'],'cgi':xdr['cgi']}
            gtpv2Pair[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'],xdr['seq'])] = state
            TEIDDict[(xdr['IPv4Addr'],xdr['sport'],xdr['TEIDKey'])] = state
            if xdr['dir'] == '0':
                xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
                xdr['SGW_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
            else:
                xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
                xdr['SGW_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
    elif xdr['msgType'] == 308:
        print(xdr['display'],xdr['msgType'],'Create Session Response')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,87,87,79,78,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
        xdr['ueIP'] = ie.get(79,0)
        xdr['pcscfIP'] = ie.get(78,0)
        xdr['sgwUTEID'] = ie.get(93,0)
        teidList = ie.get(87,0)
        if teidList != 0:
            for n in teidList:
                if n.get('interfaceType',0) == 0x8b:
                    xdr['TEIDKey'] = n.get('TEIDKey',0)
                    xdr['IPv4Addr'] = n.get('IPv4Addr',0)
        context = (xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['seq'])
        state = gtpv2Pair.get(context,0)
        if state != 0:
            state['ueIP'] = xdr['ueIP']
            xdr['imsi'] = state.get('imsi','0')
            if xdr['imsi'] != '0':
                if xdr.get('sgwUTEID',0) != 0:
                    status.teidIMSI[(xdr['sgwUTEID']['IPv4Address'],xdr['sgwUTEID']['teidKey'])] = xdr['imsi']    # tttt
            xdr['msisdn'] = state.get('msisdn','0')
            xdr['cgi'] = state.get('cgi','0')
            if xdr.get('IPv4Addr',0) != 0:
                TEIDDict[(xdr['IPv4Addr'],xdr['sport'],xdr['TEIDKey'])] = state
        if xdr['dir'] == '0':
            xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
            xdr['SGW_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
        else:
            xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
            xdr['SGW_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
    elif xdr['msgType'] == 309:
        print(xdr['display'],xdr['msgType'],'Delete Bearer Command')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 310:
        print(xdr['display'],xdr['msgType'],'Delete Bearer Failure Indication')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 311:
        print(xdr['display'],xdr['msgType'],'Delete Bearer Request')
        xdr['s11Type'] = 0
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 312:
        print(xdr['display'],xdr['msgType'],'Delete Bearer Response')
        xdr['s11Type'] = 1
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 313:
        print(xdr['display'],xdr['msgType'],'Delete Session Request')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 314:
        print(xdr['display'],xdr['msgType'],'Delete Session Response')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 315:
        print(xdr['display'],xdr['msgType'],'Modify Bearer Command')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 316:
        print(xdr['display'],xdr['msgType'],'Modify Bearer Failure Indication')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 317:
        print(xdr['display'],xdr['msgType'],'Modify Bearer Request')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 318:
        print(xdr['display'],xdr['msgType'],'Modify Bearer Response')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[1,2,76,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
        xdr['imsi'] = ie.get(1,'0')
        xdr['misdn'] = ie.get(76,'0')
    elif xdr['msgType'] == 319:
        print(xdr['display'],xdr['msgType'],'Update Bearer Request')
        xdr['s11Type'] = 0
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 320:
        print(xdr['display'],xdr['msgType'],'Update Bearer Response')
        xdr['s11Type'] = 1
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 337:
        print(xdr['display'],xdr['msgType'],'Release Access Bearers Request')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 338:
        print(xdr['display'],xdr['msgType'],'Release Access Bearers Response')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 339:
        print(xdr['display'],xdr['msgType'],'Resume ACK')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
        context = (xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['seq'])
        state = gtpv2Pair.get(context,0)
        if state != 0:
            xdr['ueIP'] = state.get('ueIP',0)
            xdr['imsi'] = state.get('imsi','0')
            xdr['msisdn'] = state.get('msisdn','0')
            xdr['cgi'] = state.get('cgi','0')
            TEIDDict[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['teid'])] = state
            if xdr['dir'] == '0':
                xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
                xdr['SGW_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
            else:
                xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
                xdr['SGW_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
    elif xdr['msgType'] == 340:
        print(xdr['display'],xdr['msgType'],'Resume Notification')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[1,73,93],xdr)
        xdr['imsi'] = ie.get(1,'0')
        state1 = {'imsi':xdr['imsi']}
        gtpv2Pair[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'],xdr['seq'])] = state1
        context = (xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['teid'])
        state= TEIDDict.get(context,0)
        if state == 0:
            state = state1
            TEIDDict[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['teid'])] = state
        else:
            state['imsi'] = xdr['imsi']
        if xdr['dir'] == '0':
            xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
            xdr['SGW_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
        else:
            xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
            xdr['SGW_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
    elif xdr['msgType'] == 341:
        print(xdr['display'],xdr['msgType'],'Suspend ACK')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
        context = (xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['seq'])
        state = gtpv2Pair.get(context,0)
        if state != 0:
            xdr['ueIP'] = state.get('ueIP',0)
            xdr['imsi'] = state.get('imsi','0')
            xdr['msisdn'] = state.get('msisdn','0')
            xdr['cgi'] = state.get('cgi','0')
            TEIDDict[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['teid'])] = state
            if xdr['dir'] == '0':
                xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
                xdr['SGW_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
            else:
                xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
                xdr['SGW_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
    elif xdr['msgType'] == 342:
        print(xdr['display'],xdr['msgType'],'Suspend Notification')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[1,73,93],xdr)
        xdr['imsi'] = ie.get(1,'0')
        state1 = {'imsi':xdr['imsi']}
        gtpv2Pair[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'],xdr['seq'])] = state1
        context = (xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['teid'])
        state= TEIDDict.get(context,0)
        if state == 0:
            state = state1
            TEIDDict[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['teid'])] = state
        else:
            state['imsi'] = xdr['imsi']
        if xdr['dir'] == '0':
            xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
            xdr['SGW_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
        else:
            xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
            xdr['SGW_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
    elif xdr['msgType'] == 399:
        print(xdr['display'],xdr['msgType'],'Downlink Data Notification')
        xdr['s11Type'] = 0
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 398:
        print(xdr['display'],xdr['msgType'],'Downlink Data Notification Ack')
        xdr['s11Type'] = 1
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 188:
        print(xdr['display'],xdr['msgType'],'Downlink Data Notification Failure Indication')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    # Sv
    elif xdr['msgType'] == 1042:
        print(xdr['display'],xdr['msgType'],'Sv: SRVCC PS To CS Handover Cancel ACK')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
        context = (xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['seq'])
        state = gtpv2Pair.get(context,0)
        if state != 0:
            xdr['imsi'] = state.get('imsi','0')
    elif xdr['msgType'] == 1043:
        print(xdr['display'],xdr['msgType'],'Sv: SRVCC PS To CS Handover Cancel NOTIFY')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[1,2,73,93],xdr)
        xdr['imsi'] = ie.get(1,'0')
        xdr['Cause'] = ie.get(2,0)
        state = {'imsi':xdr['imsi']}
        gtpv2Pair[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'],xdr['seq'])] = state
    elif xdr['msgType'] == 1044:
        print(xdr['display'],xdr['msgType'],'Sv: SRVCC PS To CS Handover Complete ACK')
        xdr['s11Type'] = 1
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
        context = (xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['seq'])
        state = gtpv2Pair.get(context,0)
        if state != 0:
            xdr['imsi'] = state.get('imsi','0')
    elif xdr['msgType'] == 1045:
        print(xdr['display'],xdr['msgType'],'Sv: SRVCC PS To CS Handover Complete NOFITY')
        xdr['s11Type'] = 0
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[1,73,93],xdr)
        xdr['imsi'] = ie.get(1,'0')
        state = {'imsi':xdr['imsi']}
        gtpv2Pair[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'],xdr['seq'])] = state
    elif xdr['msgType'] == 1046:
        print(xdr['display'],xdr['msgType'],'Sv: SRVCC PS To CS Handover REQUEST')
        xdr['s11Type'] = 0
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[1,51,76,73,93],xdr)
        xdr['imsi'] = ie.get(1,'0')
        xdr['msidn'] = ie.get(76,'0')
        if xdr['msidn'] != 0:
            xdr['msidn'] = xdr['msidn'][2:]
        xdr['stn_sr'] = ie.get(51,0)
        if xdr['stn_sr'] != 0:
            if xdr['stn_sr'] not in status.stn_sr_1: status.stn_sr_1[xdr['stn_sr']] = xdr['ts']
            if xdr['stn_sr'][:-1] not in status.stn_sr_2: status.stn_sr_2[xdr['stn_sr'][:-1]] = xdr['ts']
            if xdr['stn_sr'][:-2] not in status.stn_sr_3: status.stn_sr_3[xdr['stn_sr'][:-2]] = xdr['ts']
        if xdr['stn_sr'] != 0 and xdr['imsi'] != '0':
            status.stnSRIMSI[xdr['stn_sr']] = (xdr['imsi'],xdr['msidn'])           #0: imsi; 1: msisdn
        if xdr['msidn'] != '0' and xdr['imsi'] != '0':
            status.msisdnIMSI[xdr['msidn']] = xdr['imsi']
            status.imsiMSISDN[xdr['imsi']] = xdr['msidn']
        state = {'imsi':xdr['imsi'],'msisdn':xdr['msidn']}
        gtpv2Pair[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'],xdr['seq'])] = state
    elif xdr['msgType'] == 1047:
        print(xdr['display'],xdr['msgType'],'Sv: SRVCC PS To CS Handover RESPONSE')
        xdr['s11Type'] = 1
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
        context = (xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['seq'])
        state = gtpv2Pair.get(context,0)
        if state != 0:
            xdr['imsi'] = state.get('imsi','0')
            xdr['msisdn'] = state.get('msisdn','0')
    # N26
    elif xdr['msgType'] == 31000:
        print(xdr['display'],xdr['msgType'],'N26: Identification Request')
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 31001:
        print(xdr['display'],xdr['msgType'],'N26: Identification Response')
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 31002:
        print(xdr['display'],xdr['msgType'],'N26: Context Request')
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93,82],xdr)
        if(ie.get(82,0) == 6):
            xdr['dir'] = '0'
            if xdr['sip'][-1] not in mmeIP:     mmeIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in amfIP:     amfIP.append(xdr['dip'][-1])
        elif(ie.get(82,0) == 10):
            xdr['dir'] = '1'
            if xdr['sip'][-1] not in amfIP:     amfIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in mmeIP:     mmeIP.append(xdr['dip'][-1])
        else:
            xdr['dir'] = '-1'

    elif xdr['msgType'] == 31003:
        print(xdr['display'],xdr['msgType'],'N26: Context Response')
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93,82],xdr)
        if(ie.get(82,0) == 10):
            xdr['dir'] = '1'
            if xdr['sip'][-1] not in amfIP:     amfIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in mmeIP:     mmeIP.append(xdr['dip'][-1])
        elif(ie.get(82,0) == 6):
            xdr['dir'] = '0'
            if xdr['sip'][-1] not in mmeIP:     mmeIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in amfIP:     amfIP.append(xdr['dip'][-1])
        else:
            xdr['dir'] = '-1'

    elif xdr['msgType'] == 31004:
        print(xdr['display'],xdr['msgType'],'N26: Context Acknowledge')
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93,82],xdr)
        if(xdr['sip'][-1] in mmeIP and xdr['dip'][-1] in amfIP):
            xdr['dir'] = '0'
        elif(xdr['sip'][-1] in amfIP and xdr['dip'][-1] in mmeIP):
            xdr['dir'] = '1'
        else:
            xdr['dir'] = '-1'

    elif xdr['msgType'] == 31005:
        print(xdr['display'],xdr['msgType'],'N26: Forward Relocation Request')
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[1,76,86,87,87,71,73,93],xdr)
        xdr['imsi'] = ie.get(1,'0')
        xdr['misdn'] = ie.get(76,'0')
        if xdr['imsi'] != '0' and xdr['misdn'] != '0':
            status.msisdnIMSI[xdr['misdn']] = xdr['imsi']
            status.imsiMSISDN[xdr['imsi']] = xdr['misdn']
    elif xdr['msgType'] == 31006:
        print(xdr['display'],xdr['msgType'],'N26: Forward Relocation Response')
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 31007:
        print(xdr['display'],xdr['msgType'],'N26: Forward Relocation Complete Notification')
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 31008:
        print(xdr['display'],xdr['msgType'],'N26: Forward Relocation Complete Acknowledge')
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
    elif xdr['msgType'] == 31009:
        print(xdr['display'],xdr['msgType'],'N26: Forward Access Context Notification')
        xdr['dir'] = '1'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 31010:
        print(xdr['display'],xdr['msgType'],'N26: Forward Access Context Acknowledge')
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
        xdr['dir'] = '0'
    elif xdr['msgType'] == 31011:
        print(xdr['display'],xdr['msgType'],'N26: Relocation Cancel Request')
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 31012:
        print(xdr['display'],xdr['msgType'],'N26: Relocation Cancel Response')
        ie = getByGTPV2Code(raw[i:msgLength+4],[2,73,93],xdr)
        xdr['Cause'] = ie.get(2,0)
        xdr['dir'] = '1'
    elif xdr['msgType'] == 31013:
        print(xdr['display'],xdr['msgType'],'N26: Configuration Transfer Tunnel')
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    elif xdr['msgType'] == 31014:
        print(xdr['display'],xdr['msgType'],'N26: RAN Information Relay')
        xdr['dir'] = '0'
        ie = getByGTPV2Code(raw[i:msgLength+4],[73,93],xdr)
    else:
        print(xdr['display'], ' Unknown msgType',msgType)


    xdr['keyword1'] = msg_dict.get(xdr['msgType'],"")
    if(xdr['keyword1'] !='' and xdr['ebi'] != []):
        ebi = ",".join([str(x) for x in set(xdr['ebi'])])
        xdr['keyword1'] = xdr['keyword1']+"(EBI="+ebi+")"

    context = (xdr['dip'][len(xdr['dip'])-1],xdr['dport'],xdr['teid'])
    state = TEIDDict.get(context,0)
    if state == 0:
        pass
    else:
        xdr['imsi'] = state.get('imsi','0')
        xdr['msisdn'] = state.get('msisdn','0')
        xdr['cgi'] = state.get('cgi','0')

    tempstate = TEIDDict.get((xdr['dip'][0],xdr['dport'],xdr['teid']),0)
    if tempstate != 0:
        xdr['ueIP'] = tempstate.get('ueIP',0)
        xdr['imsi'] = tempstate.get('imsi','0')
        xdr['msisdn'] = tempstate.get('msisdn','0')
        xdr['cgi'] = tempstate.get('cgi','0')

    if 1042<= xdr['msgType'] <=1047:
        outputSVXDR(xdr)
    elif 31000 <= xdr['msgType'] <=31014 and xdr['dir'] != '-1':
        outputN26XDR(xdr)
    elif 31000 <= xdr['msgType'] <=31014 and xdr['dir'] == '-1':
        n26XDR.append(xdr)
    else:
        if xdr['dir'] == '0':
            xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
            xdr['SGW_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
        else:
            xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
            xdr['SGW_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
        outputS11XDR(xdr)
    return

# S11
def outputS11XDR(xdr):
    # Global
    global s11OutputFile,s11CPLatencyOutputFile
    # generate xdr for flowshark
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    # generate xdr for web
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'S11'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['keyword1'],'','','',str(xdr['seq']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))


    ueIP = xdr.get('ueIP',0)
    imsi = xdr.get('imsi','0')
    
    # Output xdr for flowshark
    if s11OutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        s11OutputFileName = os.path.join(status.sdlDirectory, 'LteCP_s11_Msg_'+b+'.tmp')
        s11OutputFile = open(s11OutputFileName,'w')
        if s11OutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(s11OutputFile)
    s11OutputFile.writelines(string)

    # CPLatency
    if xdr['msgType'] in [307,305,303,317,313,311,315,309,319,342,340,337]:     # request msg
        temp = s11CPLatency.get((xdr['msgType'],xdr['imsi']),0)               
        if temp != 0:
            temp.append(xdr['ts'])
        else:
            temp = [xdr['ts']]
            s11CPLatency[(xdr['msgType'],xdr['imsi'])] = temp
    
    if xdr['msgType'] in [308,306,305,304,318,314,312,319,316,317,310,320,341,339,338]:
        temp = s11CPLatency.get((s11Pair[xdr['msgType']][0],xdr['imsi']),0)
        if temp != 0:
            xdr['prcType'] = s11Pair[xdr['msgType']][1]
            if xdr['Cause'] == 16:
                xdr['SuccFlag'] = 0
            else:
                xdr['SuccFlag'] = 2
            xdr['SuccFlag'] = s11Pair[xdr['msgType']][2]
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
            del s11CPLatency[(s11Pair[xdr['msgType']][0],xdr['imsi'])]
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
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['MME_ip'])+'|'+str(xdr['SGW_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'

    if s11CPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        s11CPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S11_CPLatency_'+b+'.tmp')
        s11CPLatencyOutputFile = open(s11CPLatencyOutputFileName,'w')
        if s11CPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(s11CPLatencyOutputFile)
    s11CPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)

def cacheS11XDR(xdr):
    global gtpv2Pair
    if xdr['s11Type'] == 0:
        context = (xdr['sip'],xdr['sport'],xdr['seq'])
    else:
        context = (xdr['dip'],xdr['dport'],xdr['seq'])
    
    return

def flushS11XDR():
    for n in s11XDR:
        outputS11XDR(n)
    s11XDR.clear()

# Sv
def outputSVXDR(xdr):
    global svOutputFile,svCPLatencyOutputFile
    
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'Sv'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['keyword1'],'','','',str(xdr['seq']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if svOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        svOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_sv_Msg_'+b+'.tmp')
        svOutputFile = open(svOutputFileName,'w')
        if svOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(svOutputFile)
    svOutputFile.writelines(string)

    # CPLatency
    if xdr['msgType'] in [1043,1045,1046]:
        temp = svCPLatency.get((xdr['msgType'],xdr['imsi']),0)
        if temp != 0:
            temp.append(xdr)
            return
        else:         
            temp = [xdr]
            svCPLatency[(xdr['msgType'],xdr['imsi'])] = temp
            return

    temp = svCPLatency.get((svPair[xdr['msgType']][0],xdr['imsi']),0)
    if temp == 0:
        del xdr
        return

    xdr['prcType'] = svPair[xdr['msgType']][1]
    xdr['SuccFlag'] = 0
    xdr['Retrs'] = len(temp)
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
    del svCPLatency[(svPair[xdr['msgType']][0],xdr['imsi'])]
    
    xdr['APN_Id'] = ''
    xdr['msisdn'] = ''
    xdr['tid'] = ''
    xdr['tac'] = ''
    xdr['Timeout'] = ''
    xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
    xdr['MSC_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
    
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['MME_ip'])+'|'+str(xdr['MSC_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'

    if svCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        svCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_Sv_CPLatency_'+b+'.tmp')
        svCPLatencyOutputFile = open(svCPLatencyOutputFileName,'w')
        if svCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(svCPLatencyOutputFile)
    svCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)
    return

def cacheSVXDR(xdr):
    global gtpv2Pair
    if xdr['s11Type'] == 0:
        context = (xdr['sip'],xdr['sport'],xdr['seq'])
    else:
        context = (xdr['dip'],xdr['dport'],xdr['seq'])
    
    return

def flushSVXDR():
    global  svCPLatencyOutputFile
    for n in svXDR:
        outputSVXDR(n)
    svXDR.clear()
    for n in svCPLatency:
        xdr = svCPLatency[n][0]
        for m in svPair:
            if svPair[m][0] == xdr['msgType']:
                xdr['prcType'] =  svPair[m][1]
                break
        xdr['SuccFlag'] = 1
        xdr['Retrs'] = len(svCPLatency[n])
        if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
        xdr['Latency'] = ''
        xdr['msisdn'] = ''
        xdr['Timeout'] = ''
        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['MSC_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
        xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
        
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['MME_ip'])+'|'+str(xdr['MSC_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
        if svCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            svCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_Sv_CPLatency_'+b+'.tmp')
            svCPLatencyOutputFile = open(svCPLatencyOutputFileName,'w')
            if svCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(svCPLatencyOutputFile)
        svCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    svCPLatency.clear()
    return

# N26
def outputN26XDR(xdr):
    global n26OutputFile,n26CPLatencyOutputFile
    
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'N26'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['keyword1'],'','','',str(xdr['seq']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if n26OutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        n26OutputFileName = os.path.join(status.sdlDirectory, 'NrCP_N26_Msg_'+b+'.tmp')
        n26OutputFile = open(n26OutputFileName,'w')
        if n26OutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(n26OutputFile)
    n26OutputFile.writelines(string)

    # CPLatency
    if xdr['msgType'] in [31000, 31002, 31005, 31007, 31009, 31011,]:
        temp = n26CPLatency.get((xdr['sip'][0],xdr['sport'],xdr['dip'][0],xdr['dport'],xdr['seq']),0)
        if temp != 0:
            temp.append(xdr)
            return
        else:         
            temp = [xdr]
            n26CPLatency[(xdr['sip'][0],xdr['sport'],xdr['dip'][0],xdr['dport'],xdr['seq'])] = temp
            return
    elif xdr['msgType'] in [31003,]:
        temp = n26CPLatency.get((xdr['sip'][0],xdr['sport'],xdr['dip'][0],xdr['dport'],xdr['seq']),0)
        if temp != 0:
            temp.append(xdr)
        else:         
            temp = [xdr]
            n26CPLatency[(xdr['sip'][0],xdr['sport'],xdr['dip'][0],xdr['dport'],xdr['seq'])] = temp

    if(xdr['msgType'] in (31001, 31003, 31004, 31006, 31008, 31010, 31012,)):
        temp = n26CPLatency.get((xdr['dip'][0],xdr['dport'],xdr['sip'][0],xdr['sport'],xdr['seq']),0)
        if temp == 0:
            del xdr
            return

        xdr['prcType'] = n26Pair[xdr['msgType']][1]
        if(xdr['Cause'] == 16):
            xdr['SuccFlag'] = '0'
        else:
            xdr['SuccFlag'] = '2'
        xdr['Retrs'] = len(temp)
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
        del n26CPLatency[(xdr['dip'][0],xdr['dport'],xdr['sip'][0],xdr['sport'],xdr['seq'])]
        
        xdr['APN_Id'] = ''
        xdr['msisdn'] = ''
        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['Timeout'] = ''
        xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
        xdr['AMF_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
        
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['MME_ip'])+'|'+str(xdr['AMF_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'

        if n26CPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            n26CPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_N26_CPLatency_'+b+'.tmp')
            n26CPLatencyOutputFile = open(n26CPLatencyOutputFileName,'w')
            if n26CPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(n26CPLatencyOutputFile)
        n26CPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)

    return

def cacheN26XDR(xdr):
    global gtpv2Pair
    if xdr['s11Type'] == 0:
        context = (xdr['sip'],xdr['sport'],xdr['seq'])
    else:
        context = (xdr['dip'],xdr['dport'],xdr['seq'])
    
    return

def flushN26XDR():
    global  n26CPLatencyOutputFile
    for xdr in n26XDR:
        if xdr['msgType'] == 31002:
            if xdr['sip'][-1] in mmeIP and xdr['dip'][-1] in amfIP:
                xdr['dir'] = '0'
            elif xdr['sip'][-1] in amfIP and xdr['dip'][-1] in mmeIP:
                xdr['dir'] = '1'
            else:
                xdr['dir'] = '0'
        elif xdr['msgType'] == 31003:
            if xdr['sip'][-1] in mmeIP and xdr['dip'][-1] in amfIP:
                xdr['dir'] = '0'
            elif xdr['sip'][-1] in amfIP and xdr['dip'][-1] in mmeIP:
                xdr['dir'] = '1'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 31004:
            if xdr['sip'][-1] in mmeIP and xdr['dip'][-1] in amfIP:
                xdr['dir'] = '0'
            elif xdr['sip'][-1] in amfIP and xdr['dip'][-1] in mmeIP:
                xdr['dir'] = '1'
            else:
                xdr['dir'] = '0'
        outputN26XDR(xdr)
    n26XDR.clear()
    for n in n26CPLatency:
        xdr = n26CPLatency[n][0]
        for m in n26Pair:
            if n26Pair[m][0] == xdr['msgType']:
                xdr['prcType'] =  n26Pair[m][1]
                break
        xdr['SuccFlag'] = 1
        xdr['Retrs'] = len(n26CPLatency[n])
        if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
        xdr['Latency'] = ''
        xdr['msisdn'] = ''
        xdr['Timeout'] = ''
        xdr['tid'] = ''
        xdr['tac'] = ''
        # xdr['MSC_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
        # xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
        # 上面注释的两行代码只处理了ipv4的情况，增加对ipv6的处理
        if len(xdr['dip'][0]) == 16:
            xdr['MSC_ip'] = struct.unpack('!4I',xdr['dip'][0])[0]
        else:
            xdr['MSC_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
        if len(xdr['sip'][0]) == 16:
            xdr['MME_ip'] = struct.unpack('!4I',xdr['sip'][0])[0]
        else:
            xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
        
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['MME_ip'])+'|'+str(xdr['MSC_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
        if n26CPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            n26CPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_N26_CPLatency_'+b+'.tmp')
            n26CPLatencyOutputFile = open(n26CPLatencyOutputFileName,'w')
            if n26CPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(n26CPLatencyOutputFile)
        n26CPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    n26CPLatency.clear()
    return

mmeIP = []
amfIP = []

s11XDR = []
svXDR = []
n26XDR = []

gtpv2Pair = {}
TEIDDict = {}
ipIMSI = {}

s11OutputFile = None
s11CPLatencyOutputFile = None
s11CPLatency = {}

svOutputFile = None
svCPLatencyOutputFile = None
svCPLatency = {}

n26OutputFile = None
n26CPLatencyOutputFile = None
n26CPLatency = {}


ipInterfaceNE = {}

gtpv2Dict = {}
gtpv2Dict[68] = 303
gtpv2Dict[69] = 304
gtpv2Dict[95] = 305
gtpv2Dict[96] = 306
gtpv2Dict[32] = 307
gtpv2Dict[33] = 308
gtpv2Dict[66] = 309
gtpv2Dict[67] = 310
gtpv2Dict[99] = 311
gtpv2Dict[100] = 312
gtpv2Dict[36] = 313
gtpv2Dict[37] = 314
gtpv2Dict[64] = 315
gtpv2Dict[65] = 316
gtpv2Dict[34] = 317
gtpv2Dict[35] = 318
gtpv2Dict[97] = 319
gtpv2Dict[98] = 320
gtpv2Dict[170] = 337
gtpv2Dict[171] = 338

gtpv2Dict[176] = 399
gtpv2Dict[177] = 398
gtpv2Dict[70] = 188


gtpv2Dict[165] = 339
gtpv2Dict[164] = 340
gtpv2Dict[163] = 341
gtpv2Dict[162] = 342

gtpv2Dict[25] = 1046
gtpv2Dict[26] = 1047
gtpv2Dict[27] = 1045
gtpv2Dict[28] = 1044
gtpv2Dict[29] = 1043
gtpv2Dict[30] = 1042

# N26
gtpv2Dict[128] = 31000	# Identification Request
gtpv2Dict[129] = 31001	# Identification Response
gtpv2Dict[130] = 31002	# Context Request
gtpv2Dict[131] = 31003	# Context Response
gtpv2Dict[132] = 31004	# Context Acknowledge
gtpv2Dict[133] = 31005	# Forward Relocation Request
gtpv2Dict[134] = 31006	# Forward Relocation Response
gtpv2Dict[135] = 31007	# Forward Relocation Complete Notification
gtpv2Dict[136] = 31008	# Forward Relocation Complete Acknowledge
gtpv2Dict[137] = 31009	# Forward Access Context Notification
gtpv2Dict[138] = 31010	# Forward Access Context Acknowledge
gtpv2Dict[139] = 31011	# Relocation Cancel Request
gtpv2Dict[140] = 31012	# Relocation Cancel Response
gtpv2Dict[141] = 31013	# Configuration Transfer Tunnel
gtpv2Dict[142] = 31014	# RAN Information Relay




# Type	dir	msgNameUS	                msgNameCN	    Notes
# 1300	0	CREATE_SESSION	            创建会话	    CREATE_SESSION_REQUEST(307)->CREATE_SESSION_RESPONSE(308)
# 1301	1	CREATE_BEARER	            创建承载	    CREATE_BEARER_REQUEST(305)->CREATE_BEARER_RESPONSE(306)
# 1302	0	BEARER_RESOURCE_COMMAND  	承载资源指令	BEARER_RESOURCE_COMMAND(303)->CREATE_BEARER_REQUEST(305)/BEARER_RESOURCE__FAILURE_INDICATION(304)
# 1303	0	MODIFY_BEARER	            变更承载	    MODIFY_BEARER_REQUEST(317)->MODIFY_BEARER_RESPONSE(318)
# 1304	0	DELETE_SESSION	            删除承载	    DELETE_SESSION_REQUEST(313)->DELETE_SESSION_RESPONSE(314)
# 1305	0	CHANGE_NOTIFICATION	        变化通知	    CHANGE_NOTIFICATION_REQUEST->CHANGE_NOTIFICATION_RESPONSE
# 1306	1	DELETE_BEARER	            删除承载	    DELETE_BEARER_REQUEST(311)->DELETE_BEARER_RESPONSE(312)
# 1307	0	MODIFY_BEARER_COMMAND	    变更承载指令	MODIFY_BEARER_COMMAND(315)->UPDATE_BEARER_REQUEST(319)/MODIFY_BEARER_FAILURE_INDICATION(316)
# 1308	0	DELETE_BEARER_COMMAND	    删除承载指令	DELETE_BEARER_COMMAND(309)->MODIFY_BEARER_REQUEST(317)/DELETE_BEARER_FAILURE_INDICATION(310)
# 1309	1	UPDATE_BEARER	            更新承载	    UPDATE_BEARER_REQUEST(319)->UPDATE_BEARER_RESPONSE(320)
# 1310	0	SUSPEND_NOTIFICATION	    挂起通知	    SUSPEND_NOTIFICATION(342)->SUSPEND_ACKNOWLEDGE(341)
# 1311	0	RESUME_NOTIFICATION	        恢复通知	    RESUME_NOTIFICATION(340)->RESUME_ACKNOWLEDGE(339)
# 1312	0	RELEASE_BEARERS	            释放承载	    RELEASE_BEARERS_REQUEST(337)->RELEASE_BEARERS_RESPONSE(338)
# 1313	1	DOWNLINK_DATA_NOTIFICATION	下行数据通知	DOWNLINK_DATA_NOTIFICATION->DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE



s11Pair = {}
# 1300
s11Pair[308] = (307,1300,0)
# 1301
s11Pair[306] = (305,1301,0)
# 1302
s11Pair[305] = (303,1302,0)
s11Pair[304] = (303,1302,2)
# 1303
s11Pair[318] = (317,1303,0)
# 1304
s11Pair[314] = (313,1304,0)
# 1305
# s11Pair[335] = (336,1305)
# 1306
s11Pair[312] = (311,1306,0)
# 1307
s11Pair[319] = (315,1307,0)
s11Pair[316] = (315,1307,2)
# 1308
s11Pair[317] = (309,1308,0)
s11Pair[310] = (309,1308,2)
# 1309
s11Pair[320] = (319,1309,0)
# 1310
s11Pair[341] = (342,1310,0)
# 1311
s11Pair[339] = (340,1311,0)
# 1312
s11Pair[338] = (337,1312,0)
# 1313
s11Pair[398] = (399,1313)


# Type	dir	msgNameUS	                        msgNameCN	            Notes
# 2900	0	SRVCC PS To CS Handover	SRVCC       PS到CS切换	            Sv_SRVCC_PS2CS_REQUEST(1046)->Sv_SRVCC_PS2CS_RESPONSE(1047)
# 2901	0	SRVCC PS To CS Handover Cancel	    SRVCC PS到CS切换取消	Sv_SRVCC_PS2CS_CANCEL_NOTIFICATION(1045)->Sv_SRVCC_PS2CS_CANCEL_ACKNOWLEDGE(1044)
# 2902	0	SRVCC PS To CS Handover Complete	SRVCC PS到CS切换完成	Sv_SRVCC_PS2CS_COMPLETE_NOTIFICATION(1043)->Sv_SRVCC_PS2CS_COMPLETE_ACKNOWLEDGE(1042)

svPair = {}
# 2900
svPair[1047] = (1046,2900,0)
# 2901
svPair[1044] = (1045,2901,0)
# 2902
svPair[1042] = (1043,2902,0)

# Type  dir msgNameUS                                          msgNameCN                       Notes                                                                                           Category     XDR
# 6000  0   Identification Request(31000)                      Identification                  Identification Request(31000)->Identification Response(31001)                                   N26          NrRTI_N26_CPLatency
# 6001  1   Context Request(31002)                             Context Request                 Context Request(31002)->Context Response(31003)                                                 N26          NrRTI_N26_CPLatency
# 6002  0   Context Response(31003)                            Context Response                Context Response(31003)->Context Acknowledge(31004)                                             N26          NrRTI_N26_CPLatency
# 6003  0   Forward Relocation Request(31005)                  EPS Fallback                    Forward Relocation Request(31005)->Forward Relocation Response(31006)                           N26          NrRTI_N26_CPLatency
# 6004  1   Forward Relocation Complete Notification(31007)    EPS Fallback Notification       Forward Relocation Complete Notification(31007)->Forward Relocation Complete Acknowledge(31008) N26          NrRTI_N26_CPLatency
# 6005  1   Forward Access Context Notification(31009)         Access Context Notification     Forward Access Context Notification(31009)->Forward Access Context Acknowledge(31010)           N26          NrRTI_N26_CPLatency
# 6006  0   Relocation Cancel Request(31011)                   Relocation Cancel               Relocation Cancel Request(31011)->Relocation Cancel Response(31012)                             N26          NrRTI_N26_CPLatency


n26Pair = {}
n26Pair[31001] = (31000,6000,0)
n26Pair[31003] = (31002,6001,0)
n26Pair[31004] = (31003,6002,0)
n26Pair[31006] = (31005,6003,0)
n26Pair[31008] = (31007,6004,0)
n26Pair[31010] = (31009,6005,0)
n26Pair[31012] = (31011,6006,0)

msg_dict = {1042:"SRVCC PS To CS Handover Cancel ACK", 1043:"SRVCC PS To CS Handover Cancel NOTIFY", 1044:"SRVCC PS To CS Handover Complete ACK", 1045:"SRVCC PS To CS Handover Complete NOFITY", 1046:"SRVCC PS To CS Handover REQUEST", 1047:"SRVCC PS To CS Handover RESPONSE", 318:"(MBR) Modify Bearer Response", 306:"(CBR) Create Bearer Response", 339:"Resume ACK", 340:"Resume Notification", 341:"Suspend ACK", 342:"Suspend Notification", 317:"(MBR) Modify Bearer Request", 319:"(UBR) Update Bearer Request", 320:"(UBR) Update Bearer Response", 337:"(RBR) Release Access Bearers Request", 338:"(RBR) Release Access Bearers Response", 308:"(CSR) Create Session Response", 309:"(DBC) Delete Bearer Command", 310:"(DBF) Delete Bearer Failure Indication", 311:"(DBR) Delete Bearer Request", 312:"(DBR) Delete Bearer Response", 313:"(DSR) Delete Session Request", 314:"(DSR) Delete Session Response", 315:"(MBC) Modify Bearer Command", 316:"(MBF) Modify Bearer Failure Indication", 303:"(BRC) Bearer Resource Command", 304:"(BRF) Bearer Resource Failure Indication", 305:"(CBR) Create Bearer Request", 307:"(CSR) Create Session Request", 398:"(DDNA) Downlink Data Notification Acknowledgement", 399:"(DDN) Downlink Data Notification", 188:"(DDNF-Ind) Downlink Data Notification Failure Indication", 573:"Modify Access Bearers Request", 574:"Modify Access Bearers Response", 575:"Echo Request", 576:"Echo Response", 577:"Version Not Supported Indication", 578:"Change Notification", 579:"Trace Session Activation", 580:"Trace Session Deactivation", 581:"Stop Paging Indication", 582:"Delete PDN Connection Set Request", 583:"Delete PDN Connection Set Response", 584:"PGW Downlink Triggering Notification", 585:"Identification Request", 586:"Identification Response", 587:"Context Request", 588:"Context Response", 589:"Forward Relocation Request", 590:"Forward Relocation Complete Notification", 591:"Forward Access Context Notification", 592:"Relocation Cancel Request", 593:"Configuration Transfer Tunnel", 594:"Create Forwarding Tunnel", 595:"Create Indirect Data Forwarding Tunnel Request", 596:"Create Indirect Data Forwarding Tunnel Reponse", 597:"Delete Indirect Data Forwarding Tunnel Request", 598:"Delete Indirect Data Forwarding Tunnel Reponse", 599:"PGW Restart Notification", 31000:"Identification Request", 31001:"Identification Response", 31002:"Context Request", 31003:"Context Response", 31004:"Context Acknowledge", 31005:"Forward Relocation Request", 31006:"Forward Relocation Response", 31007:"Forward Relocation Complete Notification", 31008:"Forward Relocation Complete Acknowledge", 31009:"Forward Access Context Notification", 31010:"Forward Access Context Acknowledge", 31011:"Relocation Cancel Request", 31012:"Relocation Cancel Response", 31013:"Configuration Transfer Tunnel", 31014:"RAN Information Relay",}

