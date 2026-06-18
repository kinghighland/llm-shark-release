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

def getBySGSCode(raw,list):
    if list in (None,[]):
        print('list is empty')
        return

    out = {}
    pos = 1
    lengthRAW = len(raw)
    while pos < lengthRAW-2:
        sgsID,sgsLenth = struct.unpack('!2B',raw[pos:pos+2])
        if sgsID == 0:
            break
        pos += 2
        if sgsID in list:
            if sgsID == 1:                                         # IMSI
                nextByte = struct.unpack('!B',raw[pos:pos+1])[0]
                odd = 2 - ((nextByte>>3)&1)
                string = '{:X}'.format(nextByte>>4) + "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+sgsLenth]]) + 'F'
                imsi = string[:-odd]
                out[sgsID]=imsi
            elif sgsID == 4:                                       # LA
                lac = struct.unpack('!H',raw[pos:pos+2])[0]
                if out.get(sgsID,None) == None:
                    tempLAC = []
                    tempLAC.append(lac)
                    out[sgsID]=tempLAC
                else:
                    out[sgsID].append(lac)
            elif sgsID == 8:                                        # SGs cause
                sgsCause = struct.unpack('!B',raw[pos:pos+1])[0]
                out[sgsID]=sgsCause            
            elif sgsID == 15:                                       # Reject cause
                rejectCause = struct.unpack('!B',raw[pos:pos+1])[0]
                out[sgsID]=rejectCause
            elif sgsID == 9:                                        # MME Name
                pass            
            elif sgsID == 22:                                       # NAS
                out[sgsID]=raw[pos:pos+sgsLenth]
            elif sgsID == 32:                                       # Service Indicator
                out[sgsID]=struct.unpack('!B',raw[pos:pos+sgsLenth])[0]
            elif sgsID == 10:                                       # IMSI
                LUType = struct.unpack('!B',raw[pos:pos+1])[0]
                out[sgsID]=LUType
            elif sgsID == 14:                                       # TMSI
                out[sgsID]=struct.unpack('!I',raw[pos+1:pos+5])[0]
            elif sgsID == 35:                                       # TAC
                tac = struct.unpack('!H',raw[pos+3:pos+5])[0]
                out[sgsID]=tac
            elif sgsID == 36:                                       # CGI
                cgi = struct.unpack('!I',raw[pos+3:pos+7])[0]
                out[sgsID]=cgi
            else:
                print('SGs: sgsID=',sgsID,' unknown SGs Element ID')
            list.remove(sgsID)
        pos += sgsLenth
    return out

def getNAS(xdr,raw):
    i = 0
    pd, dtapType = struct.unpack('!2B',raw[0:2])
    i += 2
    if pd &15 != 9: return
    if dtapType == 1:                                             # CP-DATA
        length,i= struct.unpack('!B',raw[i:i+1])[0],i+1
        if length == 0:
            xdr['msgType'] = 493
            print(xdr['display'],xdr['msgType'],'SMS_CP_DATA')
            return
        msgType,i = struct.unpack('!B',raw[i:i+1])[0],i+1
        if msgType in [0,1]:                                      # 0: Message Type RP-DATA (MS to Network)
            ref,i= struct.unpack('!B',raw[i:i+1])[0],i+1          # 1: Message Type RP-DATA (Network to MS)
            len1,i= struct.unpack('!B',raw[i:i+1])[0],i+1
            i += len1
            len2,i= struct.unpack('!B',raw[i:i+1])[0],i+1
            i += len2
            len3,i= struct.unpack('!B',raw[i:i+1])[0],i+1
            if len3 == 0:
                xdr['msgType'] = 496
                print(xdr['display'],xdr['msgType'],'SMS_RP_DATA')
                return
        elif msgType in [2,3]:                                    # 2: Message Type RP-ACK (MS to Network)
            i += 2                                                # 3: Message Type RP-ACK (Network to MS)
            if i < len(raw):
                len1,i= struct.unpack('!B',raw[i:i+1])[0],i+1
            else:
                xdr['msgType'] = 497
                print(xdr['display'],xdr['msgType'],'SMS_RP_ACK')
                return
            if len1 == 0: 
                xdr['msgType'] = 497
                print(xdr['display'],xdr['msgType'],'SMS_RP_ACK')
                return
        elif msgType in [4,5]:                                    # 4: Message Type RP-ERROR (MS to Network)
            xdr['msgType'] = 498
            print(xdr['display'],xdr['msgType'],'SMS_RP_ERROR')
            return                                                # 5: Message Type RP-ERROR (Network to MS)
        elif msgType == 6:                                        # 6: Message Type RP-SMMA (MS to Network)
            xdr['msgType'] = 499
            print(xdr['display'],xdr['msgType'],'SMS_RP_SMMA')
            return
        msgType1,i= struct.unpack('!B',raw[i:i+1])[0],i+1
        if msgType1&3 == 1 and msgType == 0:                      # SMS-SUBMIT (1)
            xdr['msgType'] = 369
            print(xdr['display'],xdr['msgType'],'SMS_TP_SUBMIT')
        elif msgType1&3 == 1 and msgType == 1:                    # SMS-SUBMIT REPORT (1)
            xdr['msgType'] = 369
            print(xdr['display'],xdr['msgType'],'SMS_TP_SUBMIT_REPORT')
        elif msgType1&3 == 0 and msgType in (0,2):                # SMS-DELIVER REPORT (0)
            xdr['msgType'] = 367
            print(xdr['display'],xdr['msgType'],'SMS_TP_DELIVER_REPORT')
        elif msgType1&3 == 0 and msgType == 1:                    # SMS-DELIVER (0)
            xdr['msgType'] = 366
            print(xdr['display'],xdr['msgType'],'SMS_TP_DELIVER')
        elif msgType1&3 == 2 and msgType == 1:                    # SMS-STATUS REPORT (2)
            xdr['msgType'] = 368
            print(xdr['display'],xdr['msgType'],'SMS_TP_STATUS_REPORT')
        elif msgType1&3 == 2 and msgType == 0:                    # SMS-COMMAND (2)
            xdr['msgType'] = 365
            print(xdr['display'],xdr['msgType'],'SMS_TP_COMMAND')
    elif dtapType == 4:                                           # SMS CP-ACK
        xdr['msgType'] = 494
        print(xdr['display'],xdr['msgType'],'SMS_CP_ACK')
        pass
    elif dtapType == 16:                                          # SMS CP-ERROR
        xdr['msgType'] = 495
        print(xdr['display'],xdr['msgType'],'SMS_CP_ERROR')
        pass
    else:
        pass
    return

def decodeSGS(xdr,raw,flush):
    xdr['display'] += ', SGsAP'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','4'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,0,''

    xdr['msgType'] = sgsDict.get(base64.b16encode(raw[0:1]),0)

    IEs = getBySGSCode(raw,[1,4,4,9,10,14,32,35,36,8,15])
    xdr['imsi'] = IEs.get(1,'0')
    lac = IEs.get(4,0)
    if lac != 0:
        xdr['lac'] = lac[0]
    xdr['tmsi'] = IEs.get(14,0)
    xdr['ServiceID'] = IEs.get(32,0)

    if IEs.get(8,0) != 0:
        xdr['Cause'] = IEs.get(8,0)
    elif IEs.get(15,0) != 0:
        xdr['Cause'] = IEs.get(8,0)
    else:
        xdr['Cause'] = 0

    if xdr['msgType'] == 343:
        print(xdr['display'],xdr['msgType'],'ALERT_ACK')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 344:
        print(xdr['display'],xdr['msgType'],'ALERT_REJECT')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 345:
        print(xdr['display'],xdr['msgType'],'ALERT_REQUEST')
        xdr['dir'] = '1'
    elif xdr['msgType'] == 346:
        print(xdr['display'],xdr['msgType'],'DOWNLINKE_UNIT_DATA')
        xdr['dir'] = '1'
        IEs = getBySGSCode(raw,[22])         # 0x16 NAS
        nas1 = IEs.get(22,0)
        if nas1 != 0:
            if (struct.unpack('!B',nas1[:1])[0] & 15) == 9:
                xdr['SMS'] = True
                nas2 = getNAS(xdr,nas1)
            else:
                xdr['SMS'] = False
    elif xdr['msgType'] == 347:
        print(xdr['display'],xdr['msgType'],'EPS_DETACH_ACK')
        xdr['dir'] = '1'
    elif xdr['msgType'] == 348:
        print(xdr['display'],xdr['msgType'],'EPS_DETACH_INDICATION')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 349:
        print(xdr['display'],xdr['msgType'],'IMSI_DETACH_ACK')
        xdr['dir'] = '1'
    elif xdr['msgType'] == 350:
        print(xdr['display'],xdr['msgType'],'IMSI_DETACH_INDICATION')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 351:
        print(xdr['display'],xdr['msgType'],'LOCATION_UPDATE_ACCEPT')
        xdr['dir'] = '1'
    elif xdr['msgType'] == 352:
        print(xdr['display'],xdr['msgType'],'LOCATION_UPDATE_REJECT')
        xdr['dir'] = '1'
    elif xdr['msgType'] == 353:
        print(xdr['display'],xdr['msgType'],'LOCATION_UPDATE_REQUEST')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 354:
        print(xdr['display'],xdr['msgType'],'MM_INFOR_REQUEST')
        xdr['dir'] = '1'
    elif xdr['msgType'] == 355:
        print(xdr['display'],xdr['msgType'],'MO_CSFB_INDICATION')
        xdr['dir'] = '0'                 # need to check the document
    elif xdr['msgType'] == 356:
        print(xdr['display'],xdr['msgType'],'PAGING_REJECT')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 357:
        xdr['dir'] = '1'
        IEs = getBySGSCode(raw,[32])         # Service Indicator
        ind = IEs.get(32,0)                  # 1: CSFB; 2: SMS
        if ind == 1:
            print(xdr['display'],xdr['msgType'],'PAGING_REQUEST(CSFB)')
            xdr['msgType'] = 357
        elif ind == 2:
            print(xdr['display'],xdr['msgType'],'PAGING_REQUEST(SMS)')
            xdr['msgType'] = 358
    elif xdr['msgType'] == 359:
        print(xdr['display'],xdr['msgType'],'RELEASE_REQUEST')
        xdr['dir'] = '1'
    elif xdr['msgType'] == 360:
        print(xdr['display'],xdr['msgType'],'SERVICE_ABORT_REQUEST')
        xdr['dir'] = '1'
    elif xdr['msgType'] == 361:
        print(xdr['display'],xdr['msgType'],'SERVICE_REQUEST')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 362:
        print(xdr['display'],xdr['msgType'],'TMSI_REALLOCATION_COMPLETE')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 363:
        print(xdr['display'],xdr['msgType'],'UE_ACTIVITY_INDICATION')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 364:
        print(xdr['display'],xdr['msgType'],'UE_UNREACHABLE')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 365:
        print(xdr['display'],xdr['msgType'],'SMS_TP_COMMAND')
        pass
    elif xdr['msgType'] == 366:
        print(xdr['display'],xdr['msgType'],'SMS_TP_DELIVER')
        pass
    elif xdr['msgType'] == 367:
        print(xdr['display'],xdr['msgType'],'SMS_TP_DELIVER_REPORT')
        pass
    elif xdr['msgType'] == 368:
        print(xdr['display'],xdr['msgType'],'SMS_TP_STATUS_REPORT')
        pass
    elif xdr['msgType'] == 369:
        print(xdr['display'],xdr['msgType'],'SMS_TP_SUBMIT')
        pass
    elif xdr['msgType'] == 370:
        print(xdr['display'],xdr['msgType'],'SMS_TP_SUBMIT_REPORT')
        pass
    elif xdr['msgType'] == 387:
        print(xdr['display'],xdr['msgType'],'RESET_ACK')
        xdr['dir'] = '0'
    elif xdr['msgType'] == 388:
        print(xdr['display'],xdr['msgType'],'RESET_INDICATION')
        xdr['dir'] = '1'
    elif xdr['msgType'] == 389:
        print(xdr['display'],xdr['msgType'],'Uplink_Unit_Data')
        xdr['dir'] = '0'
        IEs = getBySGSCode(raw,[22])         # 0x16 NAS
        nas1 = IEs.get(22,0)
        if nas1 != 0:
            if (struct.unpack('!B',nas1[:1])[0] & 15) == 9:
                xdr['SMS'] = True
                nas2 = getNAS(xdr,nas1)
            else:
                xdr['SMS'] = False
    else:
        print(xdr['display'],base64.b16encode(raw[0:1]),' unknown')

    if xdr['dir'] == '0':
        xdr['MME_ip'] = xdr['sip'][0]
        xdr['MSC_ip'] = xdr['dip'][0]
    else:
        xdr['MME_ip'] = xdr['dip'][0]
        xdr['MSC_ip'] = xdr['sip'][0]

    cacheSGSXDR(xdr)
    return

def outputSGSXDR(xdr):
    global sgsOutputFile,sgsCPLatencyOutputFile
    if xdr['msgType'] != 999:
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
        ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
        if len(xdr['sip'][-1]) == 4:
            sip = inet_ntoa(xdr['sip'][-1])
            dip = inet_ntoa(xdr['dip'][-1])
        elif len(xdr['sip'][-1]) == 16:
            sip = inet_ntop(AF_INET6, xdr['sip'][-1])
            dip = inet_ntop(AF_INET6, xdr['dip'][-1])
        xdr['interface'] = 'SGs'
        if(xdr['imsi'] == '0'): xdr['imsi'] = ''
        if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
        status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr['imsi']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

        if sgsOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            sgsOutputFileName = os.path.join(status.sdlDirectory, 'LteCP_SGs_Msg_'+b+'.tmp')
            sgsOutputFile = open(sgsOutputFileName,'w')
            if sgsOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(sgsOutputFile)
        sgsOutputFile.writelines(string)

    # CPLatency
    if xdr['msgType'] in [357,358,369,353,348,350,345,388]:
        temp = sgsCPLatency.get((xdr['msgType'],xdr['imsi']),0)
        if temp != 0:
            temp.append(xdr['ts'])
        else:
            temp = [xdr['ts']]
            sgsCPLatency[(xdr['msgType'],xdr['imsi'])] = temp
    
    if xdr['msgType'] in [361,356,364,351,352,362,347,349,343,344,387,999]:
        pair = sgsPair[xdr['msgType']]
        for msg in pair:
            temp = sgsCPLatency.get((msg[0],xdr['imsi']),0)
            if temp != 0:
                xdr['prcType'] = msg[1]
                xdr['SuccFlag'] = msg[2]
                xdr['Retrs'] = len(temp)
                if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
                xdr['Retrs'] = str(xdr['Retrs'])
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
                del sgsCPLatency[(msg[0],xdr['imsi'])]
                break
            else:
                del xdr
                return
    else:
        del xdr
        return
    xdr['SmsCpCause'] = ''
    xdr['SmsRpCause'] = ''
    xdr['SmsTpCause'] = ''
    xdr['msisdn'] = ''
    xdr['tid'] = ''
    xdr['tac'] = ''
    xdr['Timeout'] = ''
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['MME_ip'])+'|'+str(xdr['MSC_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['SmsCpCause'])+'|'+str(xdr['SmsRpCause'])+'|'+str(xdr['SmsTpCause'])+'\n'

    if sgsCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        sgsCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_SGs_CPLatency_'+b+'.tmp')
        sgsCPLatencyOutputFile = open(sgsCPLatencyOutputFileName,'w')
        if sgsCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(sgsCPLatencyOutputFile)
    sgsCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)

def cacheSGSXDR(xdr):
    outputSGSXDR(xdr)

def flushSGSXDR():
    for n in sgsXDR:
        outputSGSXDR(n)
    sgsXDR.clear()

sgsXDR = []

sgsOutputFile = None
sgsCPLatencyOutputFile = None

sgsCPLatency = {}

sgsDict = {}
sgsDict[b'0E']=343
sgsDict[b'0F']=344
sgsDict[b'0D']=345
sgsDict[b'07']=346
sgsDict[b'12']=347
sgsDict[b'11']=348
sgsDict[b'14']=349
sgsDict[b'13']=350
sgsDict[b'0A']=351
sgsDict[b'0B']=352
sgsDict[b'09']=353
sgsDict[b'1A']=354
sgsDict[b'18']=355
sgsDict[b'02']=356
sgsDict[b'01']=357    # PAGING_REQUEST(CSFB)
# sgsDict[b'01']=358  # PAGING_REQUEST(SMS)
sgsDict[b'1B']=359
sgsDict[b'17']=360
sgsDict[b'06']=361
sgsDict[b'0C']=362
sgsDict[b'10']=363
sgsDict[b'1F']=364
sgsDict[b'16']=387
sgsDict[b'15']=388
sgsDict[b'08']=389

# Type	dir	msgNameUS	msgNameCN	        Notes
# 1400	1	CSFB_MT 	被叫电路域回落	    SGsAP-PAGING-REQUEST(357)(service type=1)->SGsAP-SERVICE-REQUEST(361)(service type=1)/SGsAP-PAGING-REJECT(356)/UE-UNREACHABLE(364)
# 1401	1	SMS_MT	    MT短消息	        SGsAP-PAGING-REQUEST(358)(service type=2)->SGsAP-SERVICE-REQUEST(361)/SGsAP-PAGING-REJECT(356)/UE-UNREACHABLE(364)
# obsoluted 1402	0	SMS_MO	    MO短消息	        UPLINK-DATA(369) With SMS(rp_mt=0&&tp_mt=1)->SGsAP-SERVICE-REQUEST(361)/CP-ERROR/RP-ERROR
# updated   1402	0	SMS_MO	    MO短消息	        UPLINK-DATA(369) With SMS(rp_mt=0&&tp_mt=1)->SGsAP-DOWNLINKE-UNIT-DATA(346)/CP-ERROR/RP-ERROR
# 1403	0	LOCATION_UPDATE	位置更新	    SGsAP-LOCATION-UPDATE-REQUEST(353)->SGsAP-LOCATION-UPDATE-ACCEPT(351)/TMSI-REALLOCATION-COMPLETE(362)/SGsAP-LOCATION-UPDATE-REJECT(352)
# 1404	0	EPS_DETACH	EPS脱离	            EPS-DETACH-INDICATION(348)->EPS-DETACH-ACK(347)
# 1405	0	IMSI_DETACH	IMSI脱离	        IMSI-DETACH-INDICATION(350)->IMSI-DETACH-ACK(349)
# 1406	0	ALERT	    振铃	            ALERT-REQUEST(345)->ALERT-ACK(343)/ALERT-REJECT(344)
# 1407	0	RESET	    重置	            RESET-INDICATION(388)->RESET-ACK(387)

sgsPair = {}
# 1400
sgsPair[361] = [(357,1400,0),(358,1401,0),(369,1402,0)]
sgsPair[356] = [(357,1400,2),(358,1401,2)]
sgsPair[364] = [(357,1400,2),(358,1401,2)]

# 1402
sgsPair[999] = [(369,1402,2)]   # RP-ERROR/CP-ERROR msgType is 999

# 1403
sgsPair[351] = [(353,1403,0)]
sgsPair[352] = [(353,1403,0)]
sgsPair[362] = [(353,1403,2)]

# 1404
sgsPair[347] = [(348,1404,0)]

# 1405
sgsPair[349] = [(350,1405,0)]

# 1406
sgsPair[343] = [(345,1406,0)]
sgsPair[344] = [(345,1406,2)]

# 1407
sgsPair[387] = [(388,1407,0)]
