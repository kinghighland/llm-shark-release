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
import sip

def getByDiameterCode(raw,list):
    if list in (None,[]):
        print('list is empty')
        return
    out = {}
    pos = 0
    lengthRAW = len(raw)
    while pos < lengthRAW-8 and len(list) != 0:
        avpCode,avp = struct.unpack('!2I',raw[pos:pos+8])
        avpFlag = avp >> 24
        avpLength = (((avp & 0xFFFFFF)+3)//4)*4
        if avpLength == 0:
            break
        avpPadLength = avpLength - (avp & 0xFFFFFF)
        if avpCode in list:
            if avpCode == 1:
                imsi = raw[pos+8:pos+avpLength-avpPadLength].decode()
                out[avpCode]=imsi
            elif avpCode == 268:
                cause = struct.unpack('!I',raw[pos+8:pos++12])[0]
                out[avpCode]=cause
            elif avpCode == 264:
                out[avpCode] = str(raw[pos+8:pos+avpLength-avpPadLength])
            elif avpCode == 416:                        #CC-Request-Type: INITIAL_REQUEST (1)
                CC_Request_Type = struct.unpack('!I',raw[pos+8:pos+12])[0]
                out[avpCode]=CC_Request_Type
            elif avpCode == 500:                        #AVP Code: 500 Abort-Cause
                Abort_Cause = struct.unpack('!I',raw[pos+8+4:pos+16])[0]
                out[avpCode]=Abort_Cause
            elif avpCode == 443:
                i = pos + 8
                l = pos+avpLength-avpPadLength
                type1 = None
                number = None
                while i < l - 8:
                    code1,flagAndLength = struct.unpack('!2I',raw[i:i+8])
                    len1 = flagAndLength & 0xFFFFFF
                    i += 8
                    if code1 == 450:                               # Subscription-Id-Type:
                        type1 = struct.unpack('!I',raw[i:i+4])[0]  # Subscription-Id-Type: END_USER_E164 (0)
                                                                   # Subscription-Id-Type: END_USER_IMSI (1)
                        i += 4
                    elif code1 == 444:                             # Subscription-Id-Data
                        number = str(raw[i:i+len1-8])[2:-1]
                        
                        i += len1-8
                if type1 != None and number != None:
                    sub = {'type':type1,'data':number}
                    if out.get(avpCode,None) == None:
                        tempSUB = []
                        tempSUB.append(sub)
                        out[avpCode]=tempSUB
                    else:
                        out[avpCode].append(sub)
            elif avpCode == 1413:
                i = pos + 12
                vendorID = struct.unpack('!I',raw[i:i+4])[0]
                rand = []
                while i < pos+avpLength-avpPadLength:
                    tempAVPCode,tempFlag,tempVendor = struct.unpack('!3I',raw[i:i+12])
                    tempLen = tempFlag & 0xFFFFFF
                    if tempAVPCode == 1414:
                        j = i + 12
                        while j < i+tempLen:
                            temp1AVPCode,temp1Flag,temp1Vendor = struct.unpack('!3I',raw[j:j+12])
                            temp1Len = temp1Flag & 0xFFFFFF
                            if temp1AVPCode == 1447:
                                rand.append(base64.b16encode(raw[j+12:j+28]))
                            j += temp1Len
                    i += tempLen
                    out[avpCode] = rand
            else:
                print('avpCode',avpCode,' unknown Diameter AVP Code')
            list.remove(avpCode)
        pos += avpLength
    return out

def decodeDIAMETER(xdr,raw,flush):
    xdr['display'] += ', Diameter'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','4'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''
    xdr['ip'] = 0
    version,len1,len2,flag,cc1,cc2,appid,h2h,e2e = struct.unpack('!BBHBBH3I',raw[0:20])
    length = len1*65536+len2
    commandCode = cc1*65536+cc2
    r = flag >> 7
    xdr['r'] = r
    xdr['h2h'] = h2h
    xdr['e2e'] = e2e
    xdr['diameterLength'] = length
    xdr['msgType'] = diameterDict.get((appid,r,commandCode),0)
    xdr['keyword4'] = ""


    if(xdr['msgType'] == 0):
        result_list = [x for x in diameterDict if x[1] == r and x[2] == commandCode]
        if(len(result_list) == 1):
            xdr['msgType'] = diameterDict[result_list[0]]
    if version != 1:
        print(xdr['display'], 'unknown diameter version',version)
        del xdr
        return
    if appid == 0:
        print(xdr['display'], ' ApplicationId: Diameter Common Messages (0) ',appid)
        del xdr
        return
    if appid == 16777255:
        print(xdr['display'], ' ApplicationId: SLg ',appid)
        del xdr
        return
    xdr['xType'] = str(getByDiameterCode(raw[20:],[416]).get(416,''))
    xdr['Cause'] = str(getByDiameterCode(raw[20:],[500]).get(500,''))
    if r == 1:
        string = getByDiameterCode(raw[20:],[1]).get(1,'0')
        if appid in [16777216,16777217] and string != '0':
            m = re.match('^[0-9]{15}',string)
            if m:
                xdr['imsi'] = m.group(0)
        else:
            xdr['imsi'] = string
    
    # Get Origin-Host and put it into keyword4.
    # sh interface, get AS type
    # cx interface, get CSCF type
    origin_host = getByDiameterCode(raw[20:],[264]).get(264,"")
    if origin_host != '':
        if appid == 16777217:
            xdr['keyword4'] = sip.tag_as(origin_host)
        elif appid == 16777216:
            ne_type = re.search(r'icscf|scscf|cscf',origin_host,flags=re.I)
            if ne_type != None:
                ne_type = ne_type.group().upper()
                if(ne_type == "ICSCF"):
                    xdr['keyword4'] = "I-CSCF"
                elif(ne_type == "SCSCF"):
                    xdr['keyword4'] = "S-CSCF"
        
    # S6a
    if xdr['msgType'] == 321:
        print(xdr['display'],xdr['msgType'],'S6a: (AIA) Authentication-Information-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        avps = getByDiameterCode(raw[20:],[268,1413])
        xdr['Cause'] = avps.get(268,0)
        xdr['rand'] = avps.get(1413,0)
    elif xdr['msgType'] == 322:
        print(xdr['display'],xdr['msgType'],'S6a: (AIR) Authentication-Information-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 323:
        print(xdr['display'],xdr['msgType'],'S6a: (CLA) Cancel-Location-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 324:
        print(xdr['display'],xdr['msgType'],'S6a: (CLR) Cancel-Location-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 325:
        print(xdr['display'],xdr['msgType'],'S6a: (DSA) Delete-Subscriber Data-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 326:
        print(xdr['display'],xdr['msgType'],'S6a: (DSR) Delete-Subscriber Data-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 327:
        print(xdr['display'],xdr['msgType'],'S6a: (IDA) Insert-Subscriber Data-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 328:
        print(xdr['display'],xdr['msgType'],'S6a: (IDR) Insert-Subscriber Data-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 329:
        print(xdr['display'],xdr['msgType'],'S6a: (NA) Notify-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 330:
        print(xdr['display'],xdr['msgType'],'S6a: (NR) Notify-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 331:
        print(xdr['display'],xdr['msgType'],'S6a: (PUA) Purge-UE-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 332:
        print(xdr['display'],xdr['msgType'],'S6a: (PUR) Purge-UE-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
        xdr['imsi'] = getByDiameterCode(raw[20:],[1])[1]
    elif xdr['msgType'] == 333:
        print(xdr['display'],xdr['msgType'],'S6a: (RA) Reset-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 334:
        print(xdr['display'],xdr['msgType'],'S6a: (RR) Reset-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 335:
        print(xdr['display'],xdr['msgType'],'S6a: (ULA) Update-Location-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 336:
        print(xdr['display'],xdr['msgType'],'S6a: (ULR) Update-Location-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
    # GxS7
    elif xdr['msgType'] == 600:
        print(xdr['display'],xdr['msgType'],'GxS7: (CCA) Credit-Control-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 601:
        print(xdr['display'],xdr['msgType'],'GxS7: (CCR) Credit-Control-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
        sub = getByDiameterCode(raw[20:],[443,443,416]).get(443,0)
        if sub != 0:
            for n in sub:
                if n['type'] == 1:
                    xdr['imsi'] = n['data']
                elif n['type'] == 0:
                    xdr['msisdn'] = n['data']

    elif xdr['msgType'] == 602:
        print(xdr['display'],xdr['msgType'],'GxS7: (RAA) Re-Auth-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 603:
        print(xdr['display'],xdr['msgType'],'GxS7: (RAR) Re-Auth-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    # Gy
    elif xdr['msgType'] == 604:
        print(xdr['display'],xdr['msgType'],'Gy: (CCA) Credit-Control-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 605:
        print(xdr['display'],xdr['msgType'],'Gy: (CCR) Credit-Control-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
        sub = getByDiameterCode(raw[20:],[443])
    # S13
    elif xdr['msgType'] == 998:
        print(xdr['display'],xdr['msgType'],'S13: (ECR) ME-Identity-Check-Request')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 999:
        print(xdr['display'],xdr['msgType'],'S13: (ECA) ME-Identity-Check-Answer')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    # Cx
    elif xdr['msgType'] == 1000:
        print(xdr['display'],xdr['msgType'],'Cx: (LIA) Location-Info-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1001:
        print(xdr['display'],xdr['msgType'],'Cx: (LIR) Location-Info-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 1002:
        print(xdr['display'],xdr['msgType'],'Cx: (MAA) Multimedia-Auth-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1003:
        print(xdr['display'],xdr['msgType'],'Cx: (MAR) Multimedia-Auth-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 1004:
        print(xdr['display'],xdr['msgType'],'Cx: (PPA) Push-Profile-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1005:
        print(xdr['display'],xdr['msgType'],'Cx: (PPR) Push-Profile-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 1006:
        print(xdr['display'],xdr['msgType'],'Cx: (RTA) Registration-Termination-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1007:
        print(xdr['display'],xdr['msgType'],'Cx: (RTR) Registration-Termination-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 1008:
        print(xdr['display'],xdr['msgType'],'Cx: (SAA) Server-Assignment-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1009:
        print(xdr['display'],xdr['msgType'],'Cx: (SAR) Server-Assignment-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 1010:
        print(xdr['display'],xdr['msgType'],'Cx: (UAA) User-Auth-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1011:
        print(xdr['display'],xdr['msgType'],'Cx: (UAR) User-Auth-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    # Rx
    elif xdr['msgType'] == 1026:
        print(xdr['display'],xdr['msgType'],'Rx: (AAA) AA ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1027:
        print(xdr['display'],xdr['msgType'],'Rx: (AAR) AA REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 1028:
        print(xdr['display'],xdr['msgType'],'Rx: (ASA) Abort-Session-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1029:
        print(xdr['display'],xdr['msgType'],'Rx: (ASR) Abort-Session-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 1030:
        print(xdr['display'],xdr['msgType'],'Rx: (RAA) Re-Auth-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1031:
        print(xdr['display'],xdr['msgType'],'Rx: (RAR) Re-Auth-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 1032:
        print(xdr['display'],xdr['msgType'],'Rx: (STA) Session-Termination-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1033:
        print(xdr['display'],xdr['msgType'],'Rx: (STR) Session-Termination-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    # Sh
    elif xdr['msgType'] == 1034:
        print(xdr['display'],xdr['msgType'],'Sh: (PUA) Profile-Update-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1035:
        print(xdr['display'],xdr['msgType'],'Sh: (PUR) Profile-Update-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 1036:
        print(xdr['display'],xdr['msgType'],'Sh: (PNA) Push-Notification-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '1'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1037:
        print(xdr['display'],xdr['msgType'],'Sh: (PNR) Push-Notification-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 1038:
        print(xdr['display'],xdr['msgType'],'Sh: (SNA) Subscribe-Notification-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1039:
        print(xdr['display'],xdr['msgType'],'Sh: (SNR) Subscribe-Notification-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 1040:
        print(xdr['display'],xdr['msgType'],'Sh: (UDA) User-Data-ANSWER')
        xdr['ip'] = xdr['dip'][0]
        xdr['dir'] = '0'
        xdr['Cause'] = getByDiameterCode(raw[20:],[268]).get(268,0)
    elif xdr['msgType'] == 1041:
        print(xdr['display'],xdr['msgType'],'Sh: (UDR) User-Data-REQUEST')
        xdr['ip'] = xdr['sip'][0]
        xdr['dir'] = '1'
    # Unknown
    else:
#        print('length=',length, 'Level=',xdr['Level'],'sip=',xdr['sip'][len(xdr['sip'])-1],'sport=',xdr['sport'],'dip=',xdr['dip'][len(xdr['dip'])-1],'dport=',xdr['dport'],'seq=',xdr['seq'],'tcpPayloadLength=',xdr['tcpPayloadLength'])
        if appid == 3:
            print(xdr['display'], ' Diameter Base Accounting (3)', commandCode)
        else:
            print(xdr['display'], ' Unknown Diameter Command Code and Application ID', commandCode,appid)
#        tcpList.append(xdr,raw) 16777255

    xdr['intValue'] = xdr['e2e']

    if appid == 16777216:           # Cx/Dx Interface
        xdr['interface'] = 'Cx'
        cacheCXXDR(xdr)
    elif appid == 16777238:         # Gx Interface
        xdr['interface'] = 'Gx'
        cacheGXXDR(xdr)
    elif appid == 16777236:         # Rx Interface
        xdr['interface'] = 'Rx'
        cacheRXXDR(xdr)
    elif appid == 16777252:         # S13/S13' Interface
        xdr['interface'] = 'S13'
        cacheS13XDR(xdr)
    elif appid == 16777251:         # S6a/S6d Interface
        if xdr['dir'] == '0':
            xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
            xdr['HSS_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
        else:
            xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
            xdr['HSS_ip'] = struct.unpack('!I',xdr['sip'][0])[0]

        xdr['interface'] = 'S6a'
        cacheS6AXDR(xdr)
    elif appid == 16777267:         # S9 Interface
        xdr['interface'] = 'S9'
        cacheS9XDR(xdr)
    elif appid == 16777217:         # Sh Interface
        xdr['interface'] = 'Sh'
        cacheSHXDR(xdr)
    # if r == 1 and xdr['imsi'] == '0':
        # print('aaaa r == 1 and imsi == 0',xdr['id'])
    return

def decodeTCPDIAMETER(xdr,raw,flush):
    global lastUpdateTime
    if xdr['ts'][0] - 2 >= lastUpdateTime:
        lastUpdateTime = xdr['ts'][0]
        for n in tcpBuffer:
            deleteList = []
            for m in tcpBuffer[n]:
                if tcpBuffer[n][m]['xdr']['ts'][0] < lastUpdateTime:
                    deleteList.append(m)
            for m in deleteList:
                del tcpBuffer[n][m]
    xdr['display'] += ' DIAMETER'
    if len(raw) < 20:
        length = 0
    else:
        version,len1,len2,flag,cc1,cc2,appid,h2h,e2e = struct.unpack('!BBHBBH3I',raw[0:20])
        length = len1*65536+len2
        if appid not in (4,16777216,16777217,16777236,16777238,16777251):
            length = 0
            xdr['diameterLength'] = length
        else:
            commandCode = cc1*65536+cc2
            r = flag >> 7
            xdr['h2h'] = h2h
            xdr['e2e'] = e2e
            xdr['diameterLength'] = length
            tcpContext = (xdr['Level'],xdr['sip'][len(xdr['sip'])-1],xdr['sport'],xdr['dip'][len(xdr['dip'])-1],xdr['dport'])
    tcpContext = (xdr['Level'],xdr['sip'][len(xdr['sip'])-1],xdr['sport'],xdr['dip'][len(xdr['dip'])-1],xdr['dport'])
    
    singlePacket = False
    i = 0
    chucks = []
    while i < len(raw)-20 and length > 20:
        version,len1,len2,flag,cc1,cc2,appid,h2h,e2e = struct.unpack('!BBHBBH3I',raw[i:i+20])
        length1 = len1*65536+len2
        commandCode = cc1*65536+cc2
        r = flag >> 7
        i += length1
        if i == len(raw) : singlePacket = True

    if singlePacket == True:
        tcpList[tcpContext] = xdr['seq']+xdr['tcpPayloadLength']
    else:
        bufferList = tcpBuffer.get(tcpContext,0)
        if bufferList == 0:
            buffer = {}
            buffer['seq'] = xdr['seq']
            buffer['tcpPayloadLength'] = xdr['tcpPayloadLength']
            buffer['xdr'] = xdr
            buffer['raw'] = raw
            bufferList = {}
            bufferList[buffer['seq']] = buffer
            tcpBuffer[tcpContext]= bufferList
            print(xdr['display'],' Fragments')
            return
        else:
            print(xdr['display'],' Fragments')
            buffer = {}
            buffer['seq'] = xdr['seq']
            buffer['tcpPayloadLength'] = xdr['tcpPayloadLength']
            buffer['xdr'] = xdr
            buffer['raw'] = raw
            bufferList[buffer['seq']] = buffer
            deleteList = []
            dLength = -888889
            n = min(bufferList)
            xdr = bufferList[n]['xdr']
            currentRaw = bufferList[n]['raw']
            deleteList.append(n)
            dLength = bufferList[n]['xdr']['diameterLength'] - bufferList[n]['xdr']['tcpPayloadLength']
            while dLength > 0:
                nextSeq = bufferList[n]['xdr']['seq']+bufferList[n]['xdr']['tcpPayloadLength']
                nextTCP = bufferList.get(nextSeq,0)
                if nextTCP == 0:
                    currentRaw = b''
                    break
                else:
                    currentRaw = currentRaw + nextTCP['raw']
                    nextSeq = nextTCP['xdr']['seq']+nextTCP['xdr']['tcpPayloadLength']
                    dLength = dLength - nextTCP['xdr']['tcpPayloadLength']
                    if nextTCP['xdr']['tcpPayloadLength'] == 0:
                        print('aaa',xdr['id'])
                    deleteList.append(nextTCP['xdr']['seq'])
                if dLength > 65535: exit()
            if len(currentRaw) == 0:
                return
            else:
                raw = currentRaw
                xdr['display'] += ', Frag#'+str(xdr['id'])
                for m in deleteList:
                    if m != n:
                        xdr['RawData'] = xdr['RawData'] + bufferList[m]['xdr']['RawData']
                        xdr['RawData1'] = xdr['RawData1'] + bufferList[m]['xdr']['RawData1']
                        xdr['display'] += ',Frag#'+str(bufferList[m]['xdr']['id'])
            del tcpBuffer[tcpContext]
    i = 0
    chucks = []
    while i < len(raw):
        version,len1,len2,flag,cc1,cc2,appid,h2h,e2e = struct.unpack('!BBHBBH3I',raw[i:i+20])
        length1 = len1*65536+len2
        if length1 == 0:
            break
        commandCode = cc1*65536+cc2
        r = flag >> 7
        chucks.append(raw[i:i+length1])
        i += length1
    if len(chucks) == 1:
        decodeDIAMETER(xdr,chucks[0],flush)
    elif len(chucks) > 1:
        for n in chucks:
            xdr1 = xdr.copy()
            decodeDIAMETER(xdr1,n,flush)
        del xdr
    return

def decodeSCTPDIAMETER(xdr,raw,flush):
    decodeDIAMETER(xdr,raw,flush)
    return
# Cx
def outputCXXDR(xdr):
    global cxOutputFile,cxCPLatency,cxCPLatencyOutputFile
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','',xdr['keyword4'],str(xdr['e2e']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if cxOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        cxOutputFileName = os.path.join(status.sdlDirectory,'ImsCP_cx_Msg_'+b+'.tmp')
        cxOutputFile = open(cxOutputFileName,'w')
        if cxOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(cxOutputFile)
    cxOutputFile.writelines(string)

    # CPLatency
    if xdr['msgType'] in [1005,1001,1003,1007,1009,1011]:
        temp = cxCPLatency.get((xdr['e2e'],xdr['h2h']),0)
        if temp != 0:
            temp.append(xdr)
            return
        else:
            temp = [xdr]
            cxCPLatency[(xdr['e2e'],xdr['h2h'])] = temp
            return
    
    temp = cxCPLatency.get((xdr['e2e'],xdr['h2h']),0)
    if temp == 0:
        del xdr
        return

    xdr['prcType'] = cxPair[xdr['msgType']][1]
    xdr['SuccFlag'] = 0
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
    del cxCPLatency[(xdr['e2e'],xdr['h2h'])]
    
    xdr['APN_Id'] = ''
    xdr['msisdn'] = ''
    xdr['tid'] = ''
    xdr['tac'] = ''
    xdr['Timeout'] = ''
    xdr['HHS_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
    xdr['CSCF_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
    
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['HHS_ip'])+'|'+str(xdr['CSCF_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'

    if cxCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        cxCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_Cx_CPLatency_'+b+'.tmp')
        cxCPLatencyOutputFile = open(cxCPLatencyOutputFileName,'w')
        if cxCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(cxCPLatencyOutputFile)
    cxCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)
    return
def cacheCXXDR(xdr):
    global cxSessionDict
    context = (xdr['ip'],xdr['e2e'])
    if status.cxSessionDict.get(context,0) == 0:
        state = {}
        state['imsi'] = xdr.get('imsi','0')
        state['msisdn'] = xdr.get('msisdn','0')
        state['ts'] = xdr.get('ts',0)
        status.cxSessionDict[context] = state
    else:
        imsi = status.cxSessionDict[context]['imsi']
        msisdn = status.cxSessionDict[context]['msisdn']
        if xdr.get('imsi','0') == '0' and imsi != '0':
            xdr['imsi'] = imsi
        elif xdr.get('msisdn','0') == '0' and msisdn != '0':
            xdr['msisdn'] = msisdn
        elif xdr.get('imsi','0') != '0' and imsi == '0':
            status.cxSessionDict[context]['imsi'] = xdr.get('imsi','0')
        elif xdr.get('msisdn','0') != '0' and msisdn == '0':
            status.cxSessionDict[context]['msisdn'] = xdr.get('msisdn','0')
    if xdr.get('imsi','0') != '0' or xdr.get('msisdn','0') != '0':
        outputCXXDR(xdr)
    else:
        cxXDR.append(xdr)
def flushCXXDR():
    global cxCPLatencyOutputFile
    for n in cxXDR:
        outputCXXDR(n)
    cxXDR.clear()
    for n in cxCPLatency:
        xdr = cxCPLatency[n][0]
        for m in cxPair:
            if cxPair[m][0] == xdr['msgType']:
                xdr['prcType'] =  cxPair[m][1]
                break
        xdr['SuccFlag'] = 1
        xdr['Retrs'] = len(cxCPLatency[n])
        if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
        xdr['Latency'] = ''
        xdr['msisdn'] = ''
        xdr['Timeout'] = ''
        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['CSCF_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
        xdr['HHS_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
        
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['HHS_ip'])+'|'+str(xdr['CSCF_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
        if cxCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            cxCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_Cx_CPLatency_'+b+'.tmp')
            cxCPLatencyOutputFile = open(cxCPLatencyOutputFileName,'w')
            if cxCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(cxCPLatencyOutputFile)
        cxCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    cxCPLatency.clear()
    return
# Gx
def outputGXXDR(xdr):
    global gxOutputFile,gxCPLatency,gxCPLatencyOutputFile
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr['e2e']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if gxOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        gxOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_GxS7_Msg_'+b+'.tmp')
        gxOutputFile = open(gxOutputFileName,'w')
        if gxOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(gxOutputFile)
    gxOutputFile.writelines(string)

    # CPLatency
    if xdr['msgType'] in [601,603]:
        temp = gxCPLatency.get((xdr['e2e'],xdr['h2h']),0)
        if temp != 0:
            temp.append(xdr)
            return
        else:
            temp = [xdr]
            gxCPLatency[(xdr['e2e'],xdr['h2h'])] = temp
            return
    
    temp = gxCPLatency.get((xdr['e2e'],xdr['h2h']),0)
    if temp == 0:
        del xdr
        return

    xdr['prcType'] = gxPair[xdr['msgType']][1]
    xdr['SuccFlag'] = 0
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
    del gxCPLatency[(xdr['e2e'],xdr['h2h'])]
    
    xdr['APN_Id'] = ''
    xdr['msisdn'] = ''
    xdr['tid'] = ''
    xdr['tac'] = ''
    xdr['Timeout'] = ''
    xdr['PCRF_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
    xdr['PCEF_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
    
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['PCEF_ip'])+'|'+str(xdr['PCRF_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'

    if gxCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        gxCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_GxS7_CPLatency_'+b+'.tmp')
        gxCPLatencyOutputFile = open(gxCPLatencyOutputFileName,'w')
        if gxCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(gxCPLatencyOutputFile)
    gxCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)
    del xdr
    return
def cacheGXXDR(xdr):
    global gxSessionDict
    context = (xdr['ip'],xdr['e2e'])
    if status.gxSessionDict.get(context,0) == 0:
        state = {}
        state['imsi'] = xdr.get('imsi','0')
        state['msisdn'] = xdr.get('msisdn','0')
        state['ts'] = xdr.get('ts',0)
        status.gxSessionDict[context] = state
    else:
        imsi = status.gxSessionDict[context]['imsi']
        msisdn = status.gxSessionDict[context]['msisdn']
        if xdr.get('imsi','0') == '0' and imsi != '0':
            xdr['imsi'] = imsi
        elif xdr.get('msisdn','0') == '0' and msisdn != '0':
            xdr['msisdn'] = msisdn
        elif xdr.get('imsi','0') != '0' and imsi == '0':
            status.gxSessionDict[context]['imsi'] = xdr.get('imsi','0')
        elif xdr.get('msisdn','0') != '0' and msisdn == '0':
            status.gxSessionDict[context]['msisdn'] = xdr.get('msisdn','0')
    if xdr.get('imsi','0') != '0' or xdr.get('msisdn','0') != '0':
        outputGXXDR(xdr)
    else:
        gxXDR.append(xdr)
def flushGXXDR():
    global gxCPLatencyOutputFile
    
    for n in gxXDR:
        outputGXXDR(n)
    gxXDR.clear()

    for n in gxCPLatency:
        xdr = gxCPLatency[n][0]
        for m in gxPair:
            if gxPair[m][0] == xdr['msgType']:
                xdr['prcType'] =  gxPair[m][1]
                break
        xdr['SuccFlag'] = 1
        xdr['Retrs'] = len(gxCPLatency[n])
        if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
        xdr['Latency'] = ''
        xdr['msisdn'] = ''
        xdr['Timeout'] = ''
        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['PCEF_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
        xdr['PCRF_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['PCEF_ip'])+'|'+str(xdr['PCRF_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
        if gxCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            gxCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_GxS7_CPLatency_'+b+'.tmp')
            gxCPLatencyOutputFile = open(gxCPLatencyOutputFileName,'w')
            if gxCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(gxCPLatencyOutputFile)
        gxCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    gxCPLatency.clear()
# Rx
def outputRXXDR(xdr):
    global rxOutputFile,rxCPLatency,rxCPLatencyOutputFile
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr['e2e']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if rxOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        rxOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_Rx_Msg_'+b+'.tmp')
        rxOutputFile = open(rxOutputFileName,'w')
        if rxOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(rxOutputFile)
    rxOutputFile.writelines(string)
    # CPLatency
    if xdr['msgType'] in [1027,1029,1031,1033]:
        temp = rxCPLatency.get((xdr['e2e'],xdr['h2h']),0)
        if temp != 0:
            temp.append(xdr)
            return
        else:
            temp = [xdr]
            rxCPLatency[(xdr['e2e'],xdr['h2h'])] = temp
            return
    
    temp = rxCPLatency.get((xdr['e2e'],xdr['h2h']),0)
    if temp == 0:
        del xdr
        return

    xdr['prcType'] = rxPair[xdr['msgType']][1]
    xdr['SuccFlag'] = 0
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
    del rxCPLatency[(xdr['e2e'],xdr['h2h'])]
    
    xdr['APN_Id'] = ''
    xdr['msisdn'] = ''
    xdr['tid'] = ''
    xdr['tac'] = ''
    xdr['Timeout'] = ''
    xdr['PCRF_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
    xdr['SBC_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['SBC_ip'])+'|'+str(xdr['PCRF_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'

    if rxCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        rxCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_Rx_CPLatency_'+b+'.tmp')
        rxCPLatencyOutputFile = open(rxCPLatencyOutputFileName,'w')
        if rxCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(rxCPLatencyOutputFile)
    rxCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)
    del xdr
    return
def cacheRXXDR(xdr):
    global rxSessionDict
    context = (xdr['ip'],xdr['e2e'])
    if status.rxSessionDict.get(context,0) == 0:
        state = {}
        state['imsi'] = xdr.get('imsi','0')
        state['msisdn'] = xdr.get('msisdn','0')
        state['ts'] = xdr.get('ts',0)
        status.rxSessionDict[context] = state
    else:
        imsi = status.rxSessionDict[context]['imsi']
        msisdn = status.rxSessionDict[context]['msisdn']
        if xdr.get('imsi','0') == '0' and imsi != '0':
            xdr['imsi'] = imsi
        elif xdr.get('msisdn','0') == '0' and msisdn != '0':
            xdr['msisdn'] = msisdn
        elif xdr.get('imsi','0') != '0' and imsi == '0':
            status.rxSessionDict[context]['imsi'] = xdr.get('imsi','0')
        elif xdr.get('msisdn','0') != '0' and msisdn == '0':
            status.rxSessionDict[context]['msisdn'] = xdr.get('msisdn','0')
    if xdr.get('imsi','0') != '0' or xdr.get('msisdn','0') != '0':
        outputRXXDR(xdr)
    else:
        rxXDR.append(xdr)
def flushRXXDR():
    global rxCPLatencyOutputFile
    for n in rxXDR:
        outputRXXDR(n)
    rxXDR.clear()

    for n in rxCPLatency:
        xdr = rxCPLatency[n][0]
        for m in rxPair:
            if rxPair[m][0] == xdr['msgType']:
                xdr['prcType'] =  rxPair[m][1]
                break
        xdr['SuccFlag'] = 1
        xdr['Retrs'] = len(rxCPLatency[n])
        if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
        xdr['Latency'] = ''
        xdr['msisdn'] = ''
        xdr['Timeout'] = ''
        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['SBC_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
        xdr['PCRF_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['SBC_ip'])+'|'+str(xdr['PCRF_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
        if rxCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            rxCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_Rx_CPLatency_'+b+'.tmp')
            rxCPLatencyOutputFile = open(rxCPLatencyOutputFileName,'w')
            if rxCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(rxCPLatencyOutputFile)
        rxCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    rxCPLatency.clear()
    return

# S13/S13'
def outputS13XDR(xdr):
    global s13OutputFile
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr['e2e']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if s13OutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        s13OutputFileName = os.path.join(status.sdlDirectory, 'LteCP_s13_Msg_'+b+'.tmp')
        s13OutputFile = open(s13OutputFileName,'w')
        if s13OutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(s13OutputFile)
    s13OutputFile.writelines(string)
def cacheS13XDR(xdr):
    global s13SessionDict
    context = (xdr['ip'],xdr['e2e'])
    if status.s13SessionDict.get(context,0) == 0:
        state = {}
        state['imsi'] = xdr.get('imsi','0')
        state['msisdn'] = xdr.get('msisdn','0')
        state['ts'] = xdr.get('ts',0)
        status.s13SessionDict[context] = state
    else:
        imsi = status.s13SessionDict[context]['imsi']
        msisdn = status.s13SessionDict[context]['msisdn']
        if xdr.get('imsi','0') == '0' and imsi != '0':
            xdr['imsi'] = imsi
        elif xdr.get('msisdn','0') == '0' and msisdn != '0':
            xdr['msisdn'] = msisdn
        elif xdr.get('imsi','0') != '0' and imsi == '0':
            status.s13SessionDict[context]['imsi'] = xdr.get('imsi','0')
        elif xdr.get('msisdn','0') != '0' and msisdn == '0':
            status.s13SessionDict[context]['msisdn'] = xdr.get('msisdn','0')
    if xdr.get('imsi','0') != '0' or xdr.get('msisdn','0') != '0':
        outputS13XDR(xdr)
    else:
        s13XDR.append(xdr)
def flushS13XDR():
    for n in s13XDR:
        outputS13XDR(n)
    s13XDR.clear()
# S6a
def outputS6AXDR(xdr):
    global s6aOutputFile,s6aCPLatencyOutputFile
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr['e2e']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if s6aOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        s6aOutputFileName = os.path.join(status.sdlDirectory, 'LteCP_s6a_Msg_'+b+'.tmp')
        s6aOutputFile = open(s6aOutputFileName,'w')
        if s6aOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(s6aOutputFile)
    s6aOutputFile.writelines(string)

    # CPLatency
    if xdr['msgType'] in [336,324,322,328,326,332,334,330]:
        temp = s6aCPLatency.get((xdr['msgType'],xdr['imsi']),0)
        if temp != 0:
            temp.append(xdr)
        else:
            temp = [xdr]
            s6aCPLatency[(xdr['msgType'],xdr['imsi'])] = temp
    
    if xdr['msgType'] in [335,323,321,327,325,331,333,329]:
        temp = s6aCPLatency.get((s6aPair[xdr['msgType']][0],xdr['imsi']),0)
        if temp != 0:
            xdr['prcType'] = s6aPair[xdr['msgType']][1]
            if 2001 <= xdr['Cause'] <= 2999:
                xdr['SuccFlag'] = 0
            else:
                xdr['SuccFlag'] = 2
            xdr['Retrs'] = len(temp)
            if xdr['Retrs'] > 0: xdr['Retrs'] -= 1         
            tsList = []
            for xdr1 in temp:
                tsList.append(xdr1['ts'][0]*1000000000+xdr1['ts'][1])
            temp1 = min(tsList)
            temp2 = xdr['ts'][0]*1000000000+xdr['ts'][1]
            xdr['Latency'] = str((temp2 - temp1)//1000000)
            if(xdr['Latency'] == '0'):
                xdr['Latency'] = '1'
            xdr['ts'] = (temp1//1000000000,temp1 - (temp1//1000000000)*1000000000)
            del s6aCPLatency[(s6aPair[xdr['msgType']][0],xdr['imsi'])]
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
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['MME_ip'])+'|'+str(xdr['HSS_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'

    if s6aCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        s6aCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S6a_CPLatency_'+b+'.tmp')
        s6aCPLatencyOutputFile = open(s6aCPLatencyOutputFileName,'w')
        if s6aCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(s6aCPLatencyOutputFile)
    s6aCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)
def cacheS6AXDR(xdr):
    global s6aSessionDict
    context = (xdr['ip'],xdr['e2e'])
    if status.s6aSessionDict.get(context,0) == 0:
        state = {}
        state['imsi'] = xdr.get('imsi',0)
        state['msisdn'] = xdr.get('msisdn',0)
        state['ts'] = xdr.get('ts',0)
        status.s6aSessionDict[context] = state
    else:
        imsi = status.s6aSessionDict[context]['imsi']
        msisdn = status.s6aSessionDict[context]['msisdn']
        if xdr.get('imsi','0') == '0' and imsi != '0':
            xdr['imsi'] = imsi
        elif xdr.get('msisdn','0') == '0' and msisdn != '0':
            xdr['msisdn'] = msisdn
        elif xdr.get('imsi','0') != '0' and imsi == '0':
            status.s6aSessionDict[context]['imsi'] = xdr.get('imsi','0')
        elif xdr.get('msisdn','0') != '0' and msisdn == '0':
            status.s6aSessionDict[context]['msisdn'] = xdr.get('msisdn','0')
    if xdr.get('rand',0) != 0 and xdr['imsi'] != '0':
        for n in xdr['rand']:
            status.randIMSI[n] = xdr['imsi']
    if xdr.get('imsi','0') != '0' or xdr.get('msisdn','0') != '0':
        outputS6AXDR(xdr)
    else:
        s6aXDR.append(xdr)
def flushS6AXDR():
    global s6aCPLatencyOutputFile
    for n in s6aXDR:
        outputS6AXDR(n)
    s6aXDR.clear()
    for n in s6aCPLatency:
        xdr = s6aCPLatency[n][0]
        for m in s6aPair:
            if s6aPair[m][0] == xdr['msgType']:
                xdr['prcType'] =  s6aPair[m][1]
                break
        xdr['SuccFlag'] = 1
        xdr['Retrs'] = len(s6aCPLatency[n])
        if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
        xdr['Latency'] = ''
        xdr['msisdn'] = ''
        xdr['Timeout'] = ''
        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['CSCF_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
        xdr['HHS_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['HHS_ip'])+'|'+str(xdr['CSCF_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
        if s6aCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            s6aCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_S6a_CPLatency_'+b+'.tmp')
            s6aCPLatencyOutputFile = open(s6aCPLatencyOutputFileName,'w')
            if s6aCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(s6aCPLatencyOutputFile)
        s6aCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    s6aCPLatency.clear()
    return
# S9
def outputS9XDR(xdr):
    global s9OutputFile
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr['e2e']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if s9OutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        s9OutputFileName = os.path.join(status.sdlDirectory, 'LteCP_s9_Msg_'+b+'.tmp')
        s9OutputFile = open(s9OutputFileName,'w')
        if s9OutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(s9OutputFile)
    s9OutputFile.writelines(string)
def cacheS9XDR(xdr):
    global s9SessionDict
    context = (xdr['ip'],xdr['e2e'])
    if status.s9SessionDict.get(context,0) == 0:
        state = {}
        state['imsi'] = xdr.get('imsi','0')
        state['msisdn'] = xdr.get('msisdn','0')
        state['ts'] = xdr.get('ts',0)
        status.s9SessionDict[context] = state
    else:
        imsi = status.s9SessionDict[context]['imsi']
        msisdn = status.s9SessionDict[context]['msisdn']
        if xdr.get('imsi','0') == '0' and imsi != '0':
            xdr['imsi'] = imsi
        elif xdr.get('msisdn','0') == '0' and msisdn != '0':
            xdr['msisdn'] = msisdn
        elif xdr.get('imsi','0') != '0' and imsi == '0':
            status.s9SessionDict[context]['imsi'] = xdr.get('imsi','0')
        elif xdr.get('msisdn','0') != '0' and msisdn == '0':
            status.s9SessionDict[context]['msisdn'] = xdr.get('msisdn','0')
    if xdr.get('imsi','0') != '0' or xdr.get('msisdn','0') != '0':
        outputS9XDR(xdr)
    else:
        s9XDR.append(xdr)
def flushS9XDR():
    for n in s9XDR:
        outputS9XDR(n)
    s9XDR.clear()
# Sh
def outputSHXDR(xdr):
    global shOutputFile,shCPLatency,shCPLatencyOutputFile
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','',xdr['keyword4'],str(xdr['e2e']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if shOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        shOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_Sh_Msg_'+b+'.tmp')
        shOutputFile = open(shOutputFileName,'w')
        if shOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(shOutputFile)
    shOutputFile.writelines(string)
    # CPLatency
    if xdr['msgType'] in [1035,1037,1039,1041]:
        temp = shCPLatency.get((xdr['e2e'],xdr['h2h']),0)
        if temp != 0:
            temp.append(xdr)
            return
        else:
            temp = [xdr]
            shCPLatency[(xdr['e2e'],xdr['h2h'])] = temp
            return
    
    temp = shCPLatency.get((xdr['e2e'],xdr['h2h']),0)
    if temp == 0:
        del xdr
        return

    xdr['prcType'] = shPair[xdr['msgType']][1]
    xdr['SuccFlag'] = 0
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
    del shCPLatency[(xdr['e2e'],xdr['h2h'])]
    
    xdr['APN_Id'] = ''
    xdr['msisdn'] = ''
    xdr['tid'] = ''
    xdr['tac'] = ''
    xdr['Timeout'] = ''
    xdr['HSS_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
    xdr['AS_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['HSS_ip'])+'|'+str(xdr['AS_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'

    if shCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        shCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_Sh_CPLatency_'+b+'.tmp')
        shCPLatencyOutputFile = open(shCPLatencyOutputFileName,'w')
        if shCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(shCPLatencyOutputFile)
    shCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)
    return
def cacheSHXDR(xdr):
    global shSessionDict
    context = (xdr['ip'],xdr['e2e'])
    if status.shSessionDict.get(context,0) == 0:
        state = {}
        state['imsi'] = xdr.get('imsi','0')
        state['msisdn'] = xdr.get('msisdn','0')
        state['ts'] = xdr.get('ts',0)
        status.shSessionDict[context] = state
    else:
        imsi = status.shSessionDict[context]['imsi']
        msisdn = status.shSessionDict[context]['msisdn']
        if xdr.get('imsi','0') == '0' and imsi != '0':
            xdr['imsi'] = imsi
        elif xdr.get('msisdn','0') == '0' and msisdn != '0':
            xdr['msisdn'] = msisdn
        elif xdr.get('imsi','0') != '0' and imsi == '0':
            status.shSessionDict[context]['imsi'] = xdr.get('imsi','0')
        elif xdr.get('msisdn','0') != '0' and msisdn == '0':
            status.shSessionDict[context]['msisdn'] = xdr.get('msisdn','0')
    if xdr.get('imsi','0') != '0' or xdr.get('msisdn','0') != '0':
        outputSHXDR(xdr)
    else:
        shXDR.append(xdr)
def flushSHXDR():
    global shCPLatencyOutputFile
    for n in shXDR:
        outputSHXDR(n)
    shXDR.clear()
    for n in shCPLatency:
        xdr = shCPLatency[n][0]
        for m in shPair:
            if shPair[m][0] == xdr['msgType']:
                xdr['prcType'] =  shPair[m][1]
                break
        xdr['SuccFlag'] = 1
        xdr['Retrs'] = len(shCPLatency[n])
        if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
        xdr['Latency'] = ''
        xdr['msisdn'] = ''
        xdr['Timeout'] = ''
        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['AS_ip'] = struct.unpack('!I',xdr['sip'][len(xdr['sip'])-1])[0]
        xdr['HSS_ip'] = struct.unpack('!I',xdr['dip'][len(xdr['dip'])-1])[0]
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['HSS_ip'])+'|'+str(xdr['AS_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
        if shCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            shCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_Sh_CPLatency_'+b+'.tmp')
            shCPLatencyOutputFile = open(shCPLatencyOutputFileName,'w')
            if shCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(shCPLatencyOutputFile)
        shCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
    shCPLatency.clear()
    return

def flushTCP():
    pass

lastUpdateTime = 0

cxXDR = []
gxXDR = []
rxXDR = []
s13XDR = []
s6aXDR = []
s9XDR = []
shXDR = []
tcpList = {}
tcpBuffer = {}
cxOutputFile = None
cxCPLatencyOutputFile = None
cxCPLatency = {}
gxOutputFile = None
gxCPLatencyOutputFile = None
gxCPLatency = {}
rxOutputFile = None
rxCPLatencyOutputFile = None
rxCPLatency = {}
s13OutputFile = None
s13CPLatencyOutputFile = None
s13CPLatency = {}
s6aOutputFile = None
s6aCPLatencyOutputFile = None
s6aCPLatency = {}

s9OutputFile = None
s9CPLatencyOutputFile = None
s9CPLatency = {}
shOutputFile = None
shCPLatencyOutputFile = None
shCPLatency = {}

diameterDict = {}
diameterDict[(16777251,1,316)]=336        # S6d/S6d 3GPP-Update-Location-Request
diameterDict[(16777251,0,316)]=335        # S6d/S6d 3GPP-Update-Location-Answer
diameterDict[(16777251,1,317)]=324        # S6d/S6d 3GPP-Cancel-Location-Request
diameterDict[(16777251,0,317)]=323        # S6d/S6d 3GPP-Cancel-Location-Answer
diameterDict[(16777251,1,318)]=322        # S6d/S6d 3GPP-Authentication-Information-Request
diameterDict[(16777251,0,318)]=321        # S6d/S6d 3GPP-Authentication-Information-Answer
diameterDict[(16777251,1,319)]=328        # S6d/S6d 3GPP-Insert-Subscriber-Data-Request
diameterDict[(16777251,0,319)]=327        # S6d/S6d 3GPP-Insert-Subscriber-Data-Answer
diameterDict[(16777251,1,320)]=326        # S6d/S6d 3GPP-Delete-Subscriber-Data-Request
diameterDict[(16777251,0,320)]=325        # S6d/S6d 3GPP-Delete-Subscriber-Data-Answer
diameterDict[(16777251,1,321)]=332        # S6d/S6d 3GPP-Purge-UE-Request
diameterDict[(16777251,0,321)]=331        # S6d/S6d 3GPP-Purge-UE-Answer
diameterDict[(16777251,1,322)]=334        # S6d/S6d 3GPP-Reset-Request
diameterDict[(16777251,0,322)]=333        # S6d/S6d 3GPP-Reset-Answer
diameterDict[(16777251,1,323)]=330        # S6d/S6d 3GPP-Notify-Request
diameterDict[(16777251,0,323)]=329        # S6d/S6d 3GPP-Notify-Answer
diameterDict[(16777217,1,306)]=1041       # Sh User-Data-Request
diameterDict[(16777217,0,306)]=1040       # Sh User-Data-Answer
diameterDict[(16777217,1,307)]=1035       # Sh Profile-Update-Request
diameterDict[(16777217,0,307)]=1034       # Sh Profile-Update-Answer
diameterDict[(16777217,1,308)]=1039       # Sh Subscribe-Notifications-Request
diameterDict[(16777217,0,308)]=1038       # Sh Subscribe-Notifications-Answer
diameterDict[(16777217,1,309)]=1037       # Sh Push-Notification-Request
diameterDict[(16777217,0,309)]=1036       # Sh Push-Notification-Answer
diameterDict[(16777236,1,258)]=1031       # Rx Re-Auth-Request
diameterDict[(16777236,0,258)]=1030       # Rx Re-Auth-Answer
diameterDict[(16777236,1,265)]=1027       # Rx AA-Request
diameterDict[(16777236,0,265)]=1026       # Rx AA-Answer
diameterDict[(16777236,1,274)]=1029       # Rx Abort-Session-Request
diameterDict[(16777236,0,274)]=1028       # Rx Abort-Session-Answer
diameterDict[(16777236,1,275)]=1033       # Rx Session-Termination-Request
diameterDict[(16777236,0,275)]=1032       # Rx Session-Termination-Answer
diameterDict[(4,1,272)]=605               # Gy CC-Request
diameterDict[(4,0,272)]=604               # Gy CC-Answer
diameterDict[(16777238,1,258)]=603        # GxS7 Re-Auth-Request
diameterDict[(16777238,0,258)]=602        # GxS7 Re-Auth-Answer
diameterDict[(16777238,1,272)]=601        # GxS7 CC-Request
diameterDict[(16777238,0,272)]=600        # GxS7 CC-Answer
diameterDict[(16777216,1,300)]=1011       # Cx/Dx User-Authorization-Request
diameterDict[(16777216,0,300)]=1010       # Cx/Dx User-Authorization-Answer
diameterDict[(16777216,1,301)]=1009       # Cx/Dx Server-Assignment-Request
diameterDict[(16777216,0,301)]=1008       # Cx/Dx Server-Assignment-Answer
diameterDict[(16777216,1,302)]=1001       # Cx/Dx Location-Info-Request
diameterDict[(16777216,0,302)]=1000       # Cx/Dx Location-Info-Answer
diameterDict[(16777216,1,303)]=1003       # Cx/Dx Multimedia-Auth-Request
diameterDict[(16777216,0,303)]=1002       # Cx/Dx Multimedia-Auth-Answer
diameterDict[(16777216,1,304)]=1007       # Cx/Dx Registration-Termination-Request
diameterDict[(16777216,0,304)]=1006       # Cx/Dx Registration-Termination-Answer
diameterDict[(16777216,1,305)]=1005       # Cx/Dx Push-Profile-Request
diameterDict[(16777216,0,305)]=1004       # Cx/Dx Push-Profile-Answer
diameterDict[(16777252,1,324)]=998        # S13 (ECR) ME-Identity-Check-Request
diameterDict[(16777252,0,324)]=999        # S13 (ECA) ME-Identity-Check-Answer 


# Type	dir	msgNameUS	                msgNameCN	    Notes
# 1200	0	UPDATE_LOCATION	            位置更新	    UPDATE_LOCATION_REQUEST(336)->UPDATE_LOCATION_ANSWER(335)
# 1201	0	CANCEL_LOCATION	            位置取消	    CANCEL_LOCATION_REQUEST(324)->CANCEL_LOCATION_ANSWER(323)
# 1202	0	AUTHENTICATION_INFORMATION	鉴权信息	    AUTHENTICATION_INFORMATION_REQUEST(322)->AUTHENTICATION_INFORMATION_ANSWER(321)
# 1203	0	INSERT_SUBSCRIBER_DATA	    插入用户数据	INSERT_SUBSCRIBER_DATA_REQUEST(328)->INSERT_SUBSCRIBER_DATA_ANSWER(327)
# 1204	0	DELETE_SUBSCRIBER_DATA	    删除用户数据	DELETE_SUBSCRIBER_DATA_REQUEST(326)->DELETE_SUBSCRIBER_DATA_ANSWER(325)
# 1205	0	PURGE_UE	                PURGE_UE	    PURGE_UE_REQUEST(332)->PURGE_UE_ANSWER(331)
# 1206	0	RESET	                    重置	        RESET_REQUEST(334)->RESET_ANSWER(333)
# 1207	0	NOTIFY	                    通知	        NOTIFY_REQUEST(330)->NOTIFY_ANSWER(329)


s6aPair = {}
# 1200
s6aPair[335] = (336,1200)

# 1201
s6aPair[323] = (324,1201)

# 1202
s6aPair[321] = (322,1202)

# 1203
s6aPair[327] = (328,1203)

# 1204
s6aPair[325] = (326,1204)

# 1205
s6aPair[331] = (332,1205)

# 1206
s6aPair[333] = (334,1206)

# 1207
s6aPair[329] = (330,1207)

# Type	dir	msgNameUS	                msgNameCN	    Notes
# 2700	0	Push-Profile	            推送签约数据	Cx_PUSH_PROFILE_REQUEST(1005)->Cx_PUSH_PROFILE_ANSWER(1004)
# 2701	0	Location-Info	            位置信息	    Cx_LOCATION_INFO_REQUEST(1001)->Cx_LOCATION_INFO_ANSWER(1000)
# 2702	0	Multimedia-Auth	            多媒体鉴权	    Cx_MULTIMEDIA_AUTH_REQUEST(1003)->Cx_MULTIMEDIA_AUTH_ANSWER(1002)
# 2703	0	Registration-Termination	注册中止	    Cx_REG_TERMINATION_REQUEST(1007)->Cx_REG_TERMINATION_ANSWER(1006)
# 2704	0	Server-Assignment	        分配服务器	    Cx_SERVER_ASSIGNMENT_REQUEST(1009)->Cx_SERVER_ASSIGNMENT_ANSWER(1008)
# 2705	0	User-Auth	                用户认证	    Cx_USER_AUTHORIZATION_REQUEST(1011)->Cx_USER_AUTHORIZATION_ANSWER(1010)

cxPair = {}
# 2700
cxPair[1004] = (1005,2700)
# 2701
cxPair[1000] = (1001,2701)
# 2702
cxPair[1002] = (1003,2702)
# 2703
cxPair[1006] = (1007,2703)
# 2704
cxPair[1008] = (1009,2704)
# 2705
cxPair[1010] = (1011,2705)

# Type	dir	msgNameUS	                msgNameCN	    Notes
# 1800	0	CREDIT_CONTROL	            额度控制请求	GxS7_CREDIT_CTRL_REQUEST(601)->GxS7_CREDIT_CTRL_ANSWER(600)
# 1801	1	RE_AUTHENTICATION_REQUEST 	再鉴权请求	    GxS7_RE_AUTH_REQUEST(603)->GxS7_RE_AUTH_ANSWER(602)

gxPair = {}
# 1800
gxPair[600] = (601,1800)
# 1801
gxPair[602] = (603,1801)

# Type	dir	msgNameUS	        msgNameCN	Notes
# 2500	0	AA	                鉴权授权	Rx_AA_REQUEST(1027)->Rx_AA_ANSWER(1026)
# 2501	0	Re-Auth	            再鉴权	    Rx_RE_AUTH_REQUEST(1031)->Rx_RE_AUTH_ANSWER(1030)
# 2502	0	Abort-Session	    中止会话	Rx_ABORT_SESSION_REQUEST(1029)->Rx_ABORT_SESSION_ANSWER(1028)
# 2503	0	Session-Termination	会话中止	Rx_SESSION_TERMINATION_REQUEST(1033)->Rx_SESSION_TERMINATION_ANSWER(1032)

rxPair = {}
# 2500
rxPair[1026] = (1027,2500)
# 2501
rxPair[1030] = (1031,2501)
# 2502
rxPair[1028] = (1029,2502)
# 2503
rxPair[1032] = (1033,2503)

############################################################################################################################

# Type	dir	msgNameUS	            msgNameCN   	Notes
# 2600	0	User-Data	            用户数据	    Sh_USER_DATA_REQUEST(1041)->Sh_USER_DATA_ANSWER(1040)
# 2601	0	Profile-Update	        签约数据更新	Sh_PROFILE_UPDATE_REQUEST(1035)->Sh_PROFILE_UPDATE_ANSWER(1034)
# 2602	0	Push-Notification	    推送通知	    Sh_PUSH_NOTIFICATION_REQUEST(1037)->Sh_PUSH_NOTIFICATION_ANSWER(1036)
# 2603	0	Subscribe-Notification	注册通知	    Sh_SUBSCRIBE_NOTIFICATIONS_REQUEST(1039)->Sh_SUBSCRIBE_NOTIFICATIONS_ANSWER(1038)

shPair = {}
# 2600
shPair[1040] = (1041,2600)
# 2601
shPair[1034] = (1035,2601)
# 2602
shPair[1036] = (1037,2602)
# 2603
shPair[1038] = (1039,2603)
