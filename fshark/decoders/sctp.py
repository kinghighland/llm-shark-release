import sys
import os
import struct
import base64
import datetime
from collections import Counter
import x2ap
import s1ap
import sgsap
import diameter
import m3ua
import megaco
import ngap
import f1ap

def buildSCTPDecode(xdr,raw):
    # check S1AP
    length_pos = 3
    length_value = 0
    if((raw[length_pos] >> 6) == 2):
        length_value = (raw[length_pos] & 0x3F) * 256 + raw[length_pos + 1]
        length_pos += 1
    else:
        length_value = raw[length_pos]
    if (len(raw)-length_pos-1 >= length_value and len(raw)-length_pos-1 <= length_value + 3):
        sctpPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (s1ap.decodeS1AP, "Found port S1AP")
        sctpPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (s1ap.decodeS1AP, "Found port S1AP")
        return (s1ap.decodeS1AP,'Found port S1AP')

    if xdr['dport'] in s1apPortList:
        sctpPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (s1ap.decodeS1AP,'Well known port S1AP')
        return (s1ap.decodeS1AP,'Well known port S1AP')
    elif xdr['sport'] in s1apPortList:
        sctpPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (s1ap.decodeS1AP,'Well known port S1AP')
        return (s1ap.decodeS1AP,'Well known port S1AP')

    # check NGAP
    if xdr['dport'] in ngapPortList:
        sctpPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (ngap.decodeNGAP,'Well known port NGAP')
        return (ngap.decodeNGAP,'Well known port S1AP')
    elif xdr['sport'] in ngapPortList:
        sctpPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (ngap.decodeNGAP,'Well known port NGAP')
        return (ngap.decodeNGAP,'Well known port S1AP')
    # check Diameter
    if xdr['dport'] in diameterPortList:
        sctpPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (diameter.decodeSCTPDIAMETER,'Well known port Diameter')
        return (diameter.decodeSCTPDIAMETER,'Well known port Diameter')
    elif xdr['sport'] in diameterPortList:
        sctpPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (diameter.decodeSCTPDIAMETER,'Well known port Diameter')
        return (diameter.decodeSCTPDIAMETER,'Well known port Diameter')
    found = True
    i = 0
    rawLength = len(raw)
    nextByte = struct.unpack('!B',raw[i:i+1])[0]
    if nextByte == 1 and rawLength > 28:
        version,len1,len2,flag,cc1,cc2,appid,h2h,e2e = struct.unpack('!BBHBBH3I',raw[0:20])
        length = len1*65536+len2
        if cc1 == 0:
            r = flag >> 7
            i += 20
            while i < rawLength-8:
                avpCode,avp = struct.unpack('!2I',raw[i:i+8])
                avpFlag = avp >> 24
                avpLength = (((avp & 0xFFFFFF)+3)//4)*4
                avpPadLength = avpLength - (avp & 0xFFFFFF)
                if avpCode >> 16 != 0:
                    found = False
                    break
                i += avpLength
            if found == True:
                if r == 1:
                    sctpPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (diameter.decodeSCTPDIAMETER,'Found port Diameter')
                else:
                    sctpPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (diameter.decodeSCTPDIAMETER,'Found port Diameter')
                return (diameter.decodeSCTPDIAMETER,'Found port Diameter')

    # MEGACO
    if xdr['dport'] in megacoPortList:
        sctpPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (megaco.decodeMEGACO,'Well known port MEGACO')
        return (megaco.decodeMEGACO,'Well known port MEGACO')
    elif xdr['sport'] in megacoPortList:
        sctpPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (megaco.decodeMEGACO,'Well known port MEGACO')
        return (megaco.decodeMEGACO,'Well known port MEGACO')

    # SGsAP
    if xdr['dport'] in sgsapPortList:
        sctpPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (sgsap.decodeSGS,'Well known port SGsAP')
        return (sgsap.decodeSGS,'Well known port SGsAP')
    elif xdr['sport'] in sgsapPortList:
        sctpPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (sgsap.decodeSGS,'Well known port SGsAP')
        return (sgsap.decodeSGS,'Well known port SGsAP')

    i = 0
    nextByte,i = struct.unpack('!B',raw[i:i+1])[0], i + 1
    if nextByte in (1,2,3,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,26,27,28,29,30,31):
        sgs = True
        while i < len(raw)-2:
            eleID,eleLength = struct.unpack('!2B',raw[i:i+2])
            if not (0 < eleID <= 37):
                sgs = False
                break
            if eleID == 1 and eleLength > 8:
                sgs = False
                break
            if eleID == 10 and eleLength != 1:
                sgs = False
                break
            if eleID == 4 and eleLength != 5:
                sgs = False
                break
            if eleID == 21 and eleLength != 8:
                sgs = False
                break
            if eleID == 35 and eleLength != 5:
                sgs = False
                break
            if eleID == 36 and eleLength != 7:
                sgs = False
                break
            if eleID == 16 and eleLength != 1:
                sgs = False
                break
            if eleID == 32 and eleLength != 1:
                sgs = False
                break
            if eleID == 3 and eleLength != 4:
                sgs = False
                break
            if eleID == 37 and eleLength != 1:
                sgs = False
                break
            i += 2 + eleLength
        if sgs == True:
            sctpPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (sgsap.decodeSGS,'Found port SGsAP')
            sctpPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (sgsap.decodeSGS,'Found port SGsAP')
            return (sgsap.decodeSGS,'Found port SGsAP')

    # if we can not detect the protocol of the packet, we just put it in the 
    socket1Count = sctpPortProtocol.get((xdr['sip'][len(xdr['sip'])-1],xdr['sport']),(0,'Not found port in sctpPortProtocol'))
    socket2Count = sctpPortProtocol.get((xdr['dip'][len(xdr['dip'])-1],xdr['dport']),(0,'Not found port in stpPortProtocol'))
    socket1Count_0 = socket1Count[0] + 1
    socket2Count_0 = socket2Count[0] + 1   
    sctpPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (socket1Count_0,'Unkown port counted'+str(socket1Count_0))
    sctpPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (socket2Count_0,'Unkown port counted'+str(socket2Count_0))
    return (socket1Count_0,'Unkown port counted'+str(socket1Count_0))          # Unknown Protocol

def decodeSCTP(xdr,raw):
    global cc,s1apNum,x2apNum, ngapNum
    cc += 1
    xdr['display'] += ', SCTP'
    xdr['Level'] += 1
    sport,dport,vTag,crc = struct.unpack('!2HII',raw[:12])
    xdr['sport'] = sport
    xdr['dport'] = dport
    if xdr.get('sport1', '') == '': xdr['sport1'] = sport
    if xdr.get('dport1', '') == '': xdr['dport1'] = dport
    chucks = []
    i = 0
    while i < len(raw) - 16:
        chuckType,chuckFlags,chuckLength = struct.unpack('!BBH',raw[12+i:12+i+4])
        # 小于16说明有问题
        if chuckLength < 16:
            break
        if chuckType == 0:
            print(xdr['display'],'Trunk type = DATA')
            TSN,streamID,streamSeq,payloadID = struct.unpack('!IHHI',raw[12+i+4:12+i+4+12])
            xdr['TSN'] = TSN
            xdr['streamID'] = streamID
            xdr['streamSeq'] = streamSeq
            if(chuckLength + 16 == len(raw[12:])):             # It is a special packet only found in some pcaps from liaoning.
                                                               # Payload protocal identifier is 0.
                payload = raw[12+i+4+12+16:16+12+i+4+chuckLength]
                # disable the code, because we could not find the pcaps from Liaoning.
                payload = raw[12+i+4+12:12+i+4+chuckLength]
            else:
                payload = raw[12+i+4+12:12+i+4+chuckLength]
            chuck = (chuckType,chuckFlags,chuckLength,TSN,streamID,streamSeq,payloadID,payload,xdr)
            if chuckFlags & 3 == 3:         # No fragment
                chucks.append(chuck)
            else:
                fragStream = streamSeqNumber.get((xdr['sip'][0],streamSeq),0)
                if fragStream == 0:
                    fragStream = {}
                    streamSeqNumber[(xdr['sip'][0],streamSeq)] = fragStream
                if chuckFlags & 3 == 2:       # First frag
                    print(xdr['display'], 'First fragment')
                    fragHeader = fragStream.get('header',0)
                    if fragHeader == 0:
                        fragStream['header'] = TSN
                        fragStream[TSN] = chuck
                elif chuckFlags & 3 == 1:       # Last frag
                    print(xdr['display'], 'Last fragment')
                    fragTail = fragStream.get('tailer',0)
                    if fragTail == 0:
                        fragStream['tailer'] = TSN
                        fragStream[TSN] = chuck
                else:                           # in the middle of fragment
                    print(xdr['display'], 'Middle fragment')
                    frag = fragStream.get(TSN,0)
                    if frag == 0:
                        fragStream[TSN] = chuck
                if fragStream.get('header',0) != 0 and fragStream.get('tailer',0) != 0:
                    if len(fragStream) == fragStream['tailer'] - fragStream['header'] + 3:
                        payload1 = fragStream[fragStream['header']][7]
                        rawList = fragStream[fragStream['header']][8]['RawData']
                        rawList1 = fragStream[fragStream['header']][8]['RawData1']
                        display = ', Frag#' + str(fragStream[fragStream['header']][8]['id'])
                        for i in range(fragStream['header']+1,fragStream['tailer']+1):
                            payload1 += fragStream[i][7]
                            rawList += fragStream[i][8]['RawData']
                            rawList1 += fragStream[i][8]['RawData1']
                            display += ', Frag#' + str(fragStream[i][8]['id'])
                        fragStream[fragStream['header']][8]['RawData'] = rawList
                        fragStream[fragStream['header']][8]['RawData1'] = rawList1
                        chuck = (chuckType,chuckFlags,chuckLength,TSN,streamID,streamSeq,payloadID,payload1,fragStream[fragStream['header']][8])
                        chucks.append(chuck)
                        xdr = fragStream[fragStream['header']][8]
                        xdr['display'] += display
                        del streamSeqNumber[(xdr['sip'][0],streamSeq)]
        elif chuckType == 1:
            print(xdr['display'],'Trunk type = INIT')
        elif chuckType == 2:
            print(xdr['display'],'Trunk type = INIT ACK')
        elif chuckType == 3:
            print(xdr['display'],'Trunk type = SACK')
        elif chuckType == 4:
            print(xdr['display'],'Trunk type = HEARTBEAT')
        elif chuckType == 5:
            print(xdr['display'],'Trunk type = HEARTBEAT ACK')
        elif chuckType == 6:
            print(xdr['display'],'Trunk type = ABORT')
        elif chuckType == 7:
            print(xdr['display'],'Trunk type = SHUTDOWN')
        elif chuckType == 8:
            print(xdr['display'],'Trunk type = SHUTDOWN ACK')
        elif chuckType == 9:
            print(xdr['display'],'Trunk type = ERROR')
        elif chuckType == 10:
            print(xdr['display'],'Trunk type = COOKIE ECHO')
        elif chuckType == 11:
            print(xdr['display'],'Trunk type = COOKIE ACK')
        elif chuckType == 12:
            print(xdr['display'],'Trunk type = ECNE')
        elif chuckType == 13:
            print(xdr['display'],'Trunk type = CWR')
        elif chuckType == 14:
            print(xdr['display'],'Trunk type = SHUTDOWN COMPLETE')
        else:
            print(xdr['display'],'Trunk type =',chuckType," - IETF Reserved")
            
        i += ((chuckLength+3)//4)*4

    for chuck in chucks:
        xdr1 = xdr.copy()
        if chuck[6] == 18:                             # payloadID, 18, s1ap
            s1apNum += 1
            s1ap.decodeS1AP(xdr1,chuck[7],False)
        elif chuck[6] == 60:                           # payloadID, 60, ngap
            ngapNum += 1
            ngap.decodeNGAP(xdr1,chuck[7],False)
        elif chuck[6] == 62:                           # payloadId, 62, f1ap
            f1ap.decodeF1AP(xdr1,chuck[7])
            pass
        elif chuck[6] == 27:                           # payloadID, 27, x2ap
            x2apNum += 1
            x2ap.decodeX2AP(xdr1,chuck[7],False)
        elif chuck[6] == 7:                            # payloadID,  7, H.248
            megaco.decodeMEGACO(xdr1,chuck[7],False)
        elif chuck[6] == 3:                            # payloadID,  3, M3UA
            #print(xdr1['display'], chuck[6],' M3UA')
            m3ua.decodeM3UA(xdr1,chuck[7],False)
        elif chuck[6] == 46:                           # payloadID,  3, Diameter
            diameter.decodeSCTPDIAMETER(xdr1,chuck[7],False)
            sctpPortProtocol[(xdr1['dip'][len(xdr1['dip'])-1],xdr1['dport'])] = (diameter.decodeSCTPDIAMETER,' Found port Diameter by SCTP payloadID')
            sctpPortProtocol[(xdr1['sip'][len(xdr1['sip'])-1],xdr1['sport'])] = (diameter.decodeSCTPDIAMETER,' Found port Diameter by SCTP payloadID')
        else:
            decodeFunction1 = sctpPortProtocol.get((xdr1['sip'][len(xdr1['sip'])-1],xdr1['sport']),(0,'Not found port in sctpPortProtocol'))
            if decodeFunction1[0] not in [x for x in range(0,102)]+[999]:
                decodeFunction1[0](xdr1,chuck[7],False)
            else:
                decodeFunction2 = sctpPortProtocol.get((xdr1['dip'][len(xdr1['dip'])-1],xdr1['dport']),(0,'Not found port in sctpPortProtocol'))
                if decodeFunction2[0] not in [x for x in range(0,102)]+[999]:
                    decodeFunction2[0](xdr1,chuck[7],False)
                else:
                    if decodeFunction1[0] >100:
                        print(xdr1['display'],decodeFunction1[1])
                        del xdr1
                        return
                    elif decodeFunction2[0] > 100:
                        print(xdr1['display'],decodeFunction2[1])
                        del xdr1
                        return
                    else:
                        decodeFunction = buildSCTPDecode(xdr1,chuck[7])
                        if decodeFunction[0] == 999:
                            print(xdr1['display'],decodeFunction[1])
                            del xdr1
                            return
                        elif decodeFunction[0] in [x for x in range(0,102)]+[999]:
                            print(xdr1['display'],decodeFunction[1])
                            del xdr1
                            return
                        else:
                            decodeFunction[0](xdr1,chuck[7],False)
    del xdr
    return
cc = 0
s1apNum = 0
ngapNum = 0
x2apNum = 0

sctpPortProtocol = {}
s1apPortList = [36412]
ngapPortList = [38412]
diameterPortList = [3868,3869,5001,3903]
megacoPortList = [2944]
sgsapPortList = [29118]

streamSeqNumber = {}        # frament list
