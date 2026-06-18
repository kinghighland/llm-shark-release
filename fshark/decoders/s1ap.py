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

def getByS1APCode(raw,list):
    if list in (None,[]):
        print('list is empty')
        return

    out = {}
    pos = 3
    len = 0

    if struct.unpack('!B',raw[pos:pos+1])[0] // 128 != 0:
        pos += 3
    else:
        pos += 2

    numberOfItems,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos+2
    for i in range(0,numberOfItems):
        s1apId = struct.unpack('!H',raw[pos:pos+2])[0]
        
        pos += 3
        if struct.unpack('!B',raw[pos:pos+1])[0] // 128 != 0:
            len = struct.unpack('!H',raw[pos:pos+2])[0] - 128*256
            pos += 2
        else:
            len = struct.unpack('!B',raw[pos:pos+1])[0]
            pos += 1
        if s1apId in list:
            if s1apId in (0,88):
                mmeueid = 0
                for n in raw[pos+1:pos+len]: mmeueid = mmeueid*256 + n
                out[s1apId] = mmeueid
            elif s1apId == 8:
                enbueid = 0
                for n in raw[pos+1:pos+len]: enbueid = enbueid*256 + n
                out[s1apId] = enbueid
            elif s1apId == 16:            # id-E-RABToBeSetupListBearerSUReq
                ii = pos
                seq_of_len,ii = struct.unpack('!B',raw[ii:ii+1])[0] + 1, ii + 1
                nas3 = []
                for n in range(0,seq_of_len):
                    idid,ii = struct.unpack('!H',raw[ii:ii+2])[0],ii + 3
                    if struct.unpack('!B',raw[ii:ii+1])[0] // 128 != 0:
                        idLength,ii = struct.unpack('!H',raw[ii:ii+2])[0] - 32768, ii + 2
                    else:
                        idLength,ii = struct.unpack('!B',raw[ii:ii+1])[0], ii + 1
                    i = ii
                    ii += idLength
                    i += 1
                    if struct.unpack('!B',raw[i:i+1])[0] // 128 != 0:
                        i += 3
                        nextLength1,i = (struct.unpack('1B',raw[i:i+1])[0]>>3)&7, i + 1
                        i += nextLength1 + 1
                        for m in range(1,4):
                            nextLength1,i = (struct.unpack('1B',raw[i:i+1])[0]>>5)&7, i + 1
                            i += nextLength1 + 1
                        i += 2
                    else:
                        i += 5
                    tempIP,tempTEID = struct.unpack(r'!2I',raw[i:i+8])
                    tempIMSI = status.teidIMSI.get((tempIP,tempTEID),'0')
                    i += 8
                    if struct.unpack('!B',raw[i:i+1])[0] // 128 != 0:
                        len1 = struct.unpack('!H',raw[i:i+2])[0] - 128*256
                        nas2 = raw[i:i+len1]
                    else:
                        len1 = struct.unpack('!B',raw[i:i+1])[0]
                        nas2 = raw[i:i+len1]
                    nas3.append(nas2)
                    if tempIP != 0 and tempTEID != 0:
                        out[s1apId] = (nas3,(tempIP,tempTEID))
                    else:
                        out[s1apId] = (nas3,None)
            elif s1apId == 24:            # id-E-RABToBeSetupListCtxtSUReq
                i = pos
                seq_of_len = struct.unpack('!B',raw[i:i+1])[0]
                i += 1
                idid = struct.unpack('!H',raw[i:i+2])[0]
                i += 3
                if struct.unpack('!B',raw[i:i+1])[0] // 128 != 0:
                    i += 2
                else:
                    i += 1
                nas_ind = (struct.unpack('!B',raw[i:i+1])[0] >> 6) & 1
                tempIP,tempTEID = struct.unpack(r'!4sI',raw[i+6:i+14])
                tempIMSI = status.teidIMSI.get((tempIP,tempTEID),'0')

                if nas_ind == 1:
                    i += 14
                    if struct.unpack('!B',raw[i:i+1])[0] // 128 != 0:
                        len1 = struct.unpack('!H',raw[i:i+2])[0] - 128*256
                        nas1 = raw[i:i+len1+2]
                    else:
                        len1 = struct.unpack('!B',raw[i:i+1])[0]
                        nas1 = raw[i:i+len1+1]
                    if tempIP != 0 and tempTEID != 0:
                        out[s1apId] = ([nas1],(tempIP,tempTEID,tempIMSI))
                    else:
                        out[s1apId] = ([nas1],None)
                else:
                    out[s1apId] = ([],(tempIP,tempTEID,tempIMSI))
            elif s1apId == 26:
                nas = raw[pos:pos+len]
                out[s1apId] = [nas]
                #print('NAS')
            elif s1apId == 30:                                          # id-E-RABToBeModifiedListBearerModReq
                ii = pos
                seq_of_len,ii = struct.unpack('!B',raw[ii:ii+1])[0] + 1, ii + 1
                nas4 = []
                for n in range(0,seq_of_len):
                    idid,ii = struct.unpack('!H',raw[ii:ii+2])[0],ii + 3
                    if idid != 36:
                        continue
                    if struct.unpack('!B',raw[ii:ii+1])[0] // 128 != 0:
                        idLength,ii = struct.unpack('!H',raw[ii:ii+2])[0] - 32768, ii + 2
                    else:
                        idLength,ii = struct.unpack('!B',raw[ii:ii+1])[0], ii + 1
                    i = ii
                    ii += idLength
                    # i += 4   not always 4 bytes
                    nextBytes1 = struct.unpack('!B',raw[i+1:i+2])[0]
                    gbrQosInformation = (nextBytes1>>7) & 1
                    if gbrQosInformation == 1:
                        i += 4
                        len1 = (struct.unpack('!B',raw[i:i+1])[0] >> 3) & 7
                        i += len1 + 2
                        len1 = (struct.unpack('!B',raw[i:i+1])[0] >> 5) & 7
                        i += len1 + 2
                        len1 = (struct.unpack('!B',raw[i:i+1])[0] >> 5) & 7
                        i += len1 + 2
                        len1 = (struct.unpack('!B',raw[i:i+1])[0] >> 5) & 7
                        i += len1 + 2                        
                    else:
                        i += 4
                    if struct.unpack('!B',raw[i:i+1])[0] // 128 != 0:
                        len1 = struct.unpack('!H',raw[i:i+2])[0] - 128*256
                        nas2 = raw[i:i+2+len1]
                    else:
                        len1 = struct.unpack('!B',raw[i:i+1])[0]
                        nas2 = raw[i:i+1+len1]
                    nas4.append(nas2)

                out[s1apId] = (nas4)
            elif s1apId == 33:                                          # id-E-RABToBeReleasedList
                ii = pos
                seq_of_len,ii = struct.unpack('!B',raw[ii:ii+1])[0] + 1, ii + 1

                nas4 = []
                for n in range(0,seq_of_len):
                    idid,ii = struct.unpack('!H',raw[ii:ii+2])[0],ii + 3
                    if idid != 36:
                        continue

                    if struct.unpack('!B',raw[ii:ii+1])[0] // 128 != 0:
                        idLength,ii = struct.unpack('!H',raw[ii:ii+2])[0] - 32768, ii + 2
                    else:
                        idLength,ii = struct.unpack('!B',raw[ii:ii+1])[0], ii + 1

                    i = ii
                    ii += idLength
                    i += 4

                    if struct.unpack('!B',raw[i:i+1])[0] // 128 != 0:
                        len1 = struct.unpack('!H',raw[i:i+2])[0] - 128*256
                        nas2 = raw[i:i+2+len1]
                    else:
                        len1 = struct.unpack('!B',raw[i:i+1])[0]
                        nas2 = raw[i:i+1+len1]
                    nas4.append(nas2)

                out[s1apId] = (nas4)
                
            elif s1apId == 43:                                          # id-UEPagingID
                uePagingID = (struct.unpack('!B',raw[pos:pos+1])[0] >> 6 )& 1
                if uePagingID == 0:
                    mmeCode, MTMSI = struct.unpack('!HI',raw[pos:pos+len])
                    mmeCode = (mmeCode >> 4) & 255
                    out[s1apId] = (uePagingID,mmeCode, MTMSI)
                else:
                    string = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+len]])
                    imsi = string[:-1]
                    out[s1apId] = (uePagingID,imsi)
                #print('id-UEPagingID (43)')
            elif s1apId == 67:
                TAID = struct.unpack('!H',raw[pos+4:pos+6])[0]
                out[s1apId] = TAID
                #print('TAID:',TAID)
            elif s1apId == 95:                                          # TEID list
                i = pos
                len1,i = struct.unpack('!B',raw[i:i+1])[0]+1,i+1
                for n in range(0,len1):
                    s1apid,i = struct.unpack('!H',raw[i:i+2])[0],i+3
                    if struct.unpack('!B',raw[i:i+1])[0] // 128 != 0:
                        len1,i = struct.unpack('!H',raw[i:i+2])[0] - 128*256,i+2
                    else:
                        len1,i = struct.unpack('!B',raw[i:i+1])[0],i+1
                    ipv4Address,teid1 = struct.unpack('!2I',raw[i+2:i+10])
                out[s1apId] = (ipv4Address,teid1)
            elif s1apId == 96:                                          # S-TMSI
                mmeCode = (struct.unpack('!H',raw[pos:pos+2])[0] >> 6) & 0xFF
                TMSI = struct.unpack('!I',raw[pos+2:pos+6])[0]
                out[s1apId] = (mmeCode,TMSI)
            elif s1apId == 99:                                          # id-UE-S1AP-IDs
                i = pos
                len1 = ((struct.unpack('!B',raw[i:i+1])[0] >> 2) & 3) + 1
                mmeueid = 0
                i += 1
                for n in raw[i:i+len1]:
                    mmeueid = mmeueid * 256 + n
                i += len1
                len2 = ((struct.unpack('!B',raw[i:i+1])[0] >> 6) & 3) + 1
                enbueid = 0
                i += 1
                for n in raw[i:i+len2]:
                    enbueid = enbueid * 256 + n
                out[s1apId] = (mmeueid,enbueid)
            elif s1apId == 100:
                ecgi = struct.unpack('!I',raw[pos+4:pos+8])[0] // 16
                out[s1apId] = ecgi
                #print('ecgi:',ecgi)
            elif s1apId == 134:
                cause = (struct.unpack('!B',raw[pos:pos+1])[0] >> 4) & 7
                out[s1apId] = cause
                #print('cause:',cause)
            else:
                #print('Not decoded s1apId:',s1apId)
                out[s1apId] = s1apId
            list.remove(s1apId)
        if list == []:
            break
        pos += len
    return out

def decodeESM(xdr,raw):
    xdr['display'] += ', ESM'

    pos = 2
    type = struct.unpack('!B',raw[pos:pos+1])[0] & 15
    pos += 2
    if type == 2:
        xdr['msgType'] = esmDict.get(base64.b16encode(raw[pos:pos+1]),0)
    else:
        print(xdr['display'], ' Unknown type', type)

    if xdr['msgType'] == 200:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT')
        pass
    elif xdr['msgType'] == 201:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT')
        pass
    elif xdr['msgType'] == 202:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST')
        pass
    elif xdr['msgType'] == 203:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT')
        pass
    elif xdr['msgType'] == 204:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT')
        pass
    elif xdr['msgType'] == 205:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST')
        pass
    elif xdr['msgType'] == 214:
        print(xdr['display'],xdr['msgType'],'BEARER_RESOURCE_ALLOCATION_REJECT')
        pass
    elif xdr['msgType'] == 215:
        print(xdr['display'],xdr['msgType'],'BEARER_RESOURCE_ALLOCATION_REQUEST')
        pass
    elif xdr['msgType'] == 216:
        print(xdr['display'],xdr['msgType'],'BEARER_RESOURCE_MODIFICATION_REJECT')
        pass
    elif xdr['msgType'] == 217:
        print(xdr['display'],xdr['msgType'],'BEARER_RESOURCE_MODIFICATION_REQUEST')
        pass
    elif xdr['msgType'] == 219:
        print(xdr['display'],xdr['msgType'],'DEACTIVATE_EPS_CONTEXT_ACCEPT')
        pass
    elif xdr['msgType'] == 220:
        print(xdr['display'],xdr['msgType'],'DEACTIVATE_EPS_CONTEXT_REQUEST')
        pass
    elif xdr['msgType'] == 225:
        print(xdr['display'],xdr['msgType'],'ESM_INFORMATION_REQUEST')
        pass
    elif xdr['msgType'] == 226:
        print(xdr['display'],xdr['msgType'],'ESM_INFORMATION_RESPONSE')
        pass
    elif xdr['msgType'] == 227:
        print(xdr['display'],xdr['msgType'],'ESM_STSTUS')
        pass
    elif xdr['msgType'] == 233:
        print(xdr['display'],xdr['msgType'],'MODIFY_EPS_BEARER_CONTEXT_ACCEPT')
        pass
    elif xdr['msgType'] == 234:
        print(xdr['display'],xdr['msgType'],'MODIFY_EPS_BEARER_CONTEXT_REJECT')
        pass
    elif xdr['msgType'] == 235:
        print(xdr['display'],xdr['msgType'],'MODIFY_EPS_BEARER_CONTEXT_REQUEST')
        pass
    elif xdr['msgType'] == 236:
        print(xdr['display'],xdr['msgType'],'ESM_NOTIFICATION')
        pass
    elif xdr['msgType'] == 237:
        print(xdr['display'],xdr['msgType'],'PDN_CONNECTIVITY_REJECT')
        pass
    elif xdr['msgType'] == 238:
        print(xdr['display'],xdr['msgType'],'PDN_CONNECTIVITY_REQUEST')
        pass
    elif xdr['msgType'] == 239:
        print(xdr['display'],xdr['msgType'],'PDN_DISCONNECT_REJECT')
        pass
    elif xdr['msgType'] == 240:
        print(xdr['display'],xdr['msgType'],'PDN_DISCONNECT_REQUEST')
        pass

    return xdr

def getNAS(xdr,raw):
    i = 0
    pd, dtapType = struct.unpack('!2B',raw[0:2])
    i += 2
    if pd &15 != 9: return
    if dtapType == 1:                                             # CP-DATA
        length,i= struct.unpack('!B',raw[i:i+1])[0],i+1
        if length == 0:
            xdr['msgType'] = 189
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
                xdr['msgType'] = 192
                print(xdr['display'],xdr['msgType'],'SMS_RP_DATA')
                return
        elif msgType in [2,3]:                                    # 2: Message Type RP-ACK (MS to Network)
            i += 2                                                # 3: Message Type RP-ACK (Network to MS)
            if i < len(raw):
                len1,i= struct.unpack('!B',raw[i:i+1])[0],i+1
            else:
                xdr['msgType'] = 193
                print(xdr['display'],xdr['msgType'],'SMS_RP_ACK')
                return
            if len1 == 0: 
                xdr['msgType'] = 193
                print(xdr['display'],xdr['msgType'],'SMS_RP_ACK')
                return
        elif msgType in [4,5]:                                    # 4: Message Type RP-ERROR (MS to Network)
            xdr['msgType'] = 194
            print(xdr['display'],xdr['msgType'],'SMS_RP_ERROR')
            return                                                # 5: Message Type RP-ERROR (Network to MS)
        elif msgType == 6:                                        # 6: Message Type RP-SMMA (MS to Network)
            xdr['msgType'] = 195
            print(xdr['display'],xdr['msgType'],'SMS_RP_SMMA')
            return
        msgType1,i= struct.unpack('!B',raw[i:i+1])[0],i+1
        if msgType1&3 == 1 and msgType == 0:                      # SMS-SUBMIT (1)
            xdr['msgType'] = 384
            print(xdr['display'],xdr['msgType'],'SMS_TP_SUBMIT')
        elif msgType1&3 == 1 and msgType == 1:                    # SMS-SUBMIT REPORT (1)
            xdr['msgType'] = 385
            print(xdr['display'],xdr['msgType'],'SMS_TP_SUBMIT_REPORT')
        elif msgType1&3 == 0 and msgType in (0,2):                # SMS-DELIVER REPORT (0)
            xdr['msgType'] = 382
            print(xdr['display'],xdr['msgType'],'SMS_TP_DELIVER_REPORT')
        elif msgType1&3 == 0 and msgType == 1:                    # SMS-DELIVER (0)
            xdr['msgType'] = 381
            print(xdr['display'],xdr['msgType'],'SMS_TP_DELIVER')
        elif msgType1&3 == 2 and msgType == 1:                    # SMS-STATUS REPORT (2)
            xdr['msgType'] = 383
            print(xdr['display'],xdr['msgType'],'SMS_TP_STATUS_REPORT')
        elif msgType1&3 == 2 and msgType == 0:                    # SMS-COMMAND (2)
            xdr['msgType'] = 380
            print(xdr['display'],xdr['msgType'],'SMS_TP_COMMAND')
    elif dtapType == 4:                                           # SMS CP-ACK
        xdr['msgType'] = 190
        print(xdr['display'],xdr['msgType'],'SMS_CP_ACK')
        pass
    elif dtapType == 16:                                          # SMS CP-ERROR
        xdr['msgType'] = 191
        print(xdr['display'],xdr['msgType'],'SMS_CP_ERROR')
        pass
    else:
        pass
    return

def decodeNAS(xdr,raw):
    xdr['display'] += ', NAS'
    pos = 0
    if struct.unpack('!B',raw[pos:pos+1])[0] // 128 != 0:
        pos += 2
    else:
        pos += 1
    nextByte = raw[pos:pos+1]
    if nextByte == b'\xC7':                   # Service Request
        xdr['msgType'] = 245
        print(xdr['display'],xdr['msgType'],'SERVICE_REQUEST')
    elif nextByte == b'\x07':
        pos += 1
        xdr['msgType'] = emmDict.get(base64.b16encode(raw[pos:pos+1]),0)
    elif nextByte == b'\x27':
        pos += 6
        nextByte = struct.unpack('!B',raw[pos:pos+1])[0] % 16
        if nextByte == 7:
            pos += 1
            xdr['msgType'] = emmDict.get(base64.b16encode(raw[pos:pos+1]),0)
        elif nextByte == 2:
            pos += 2
            xdr['msgType'] = esmDict.get(base64.b16encode(raw[pos:pos+1]),0)
        else:
            print(xdr['display'],', Unknown NAS Protocol discriminator:', nextByte)
    elif (struct.unpack('!B',nextByte)[0] & 15) == 2:
        pos += 2
        xdr['msgType'] = esmDict.get(base64.b16encode(raw[pos:pos+1]),0)
    else:
        pos += 6
        nextByte = struct.unpack('!B',raw[pos:pos+1])[0] % 16
        if nextByte == 7:
            pos += 1
            xdr['msgType'] = emmDict.get(base64.b16encode(raw[pos:pos+1]),0)
        elif nextByte == 2:
            pos += 2
            xdr['msgType'] = esmDict.get(base64.b16encode(raw[pos:pos+1]),0)
        else:
            print(xdr['display'],', Unknown NAS Protocol discriminator:', nextByte)
    esmXDR = None

    if xdr['msgType'] == 206:
        print(xdr['display'],xdr['msgType'],'ATTACH_ACCEPT')
        pos += 1
        xdr['AttachResult'] = struct.unpack('!B',raw[pos:pos+1])[0] & 7
        pos += 2
        len1 = struct.unpack('!B',raw[pos:pos+1])[0]
        pos += 1 + len1
        len1 = struct.unpack('!H',raw[pos:pos+2])[0]
        xdr1 = xdr.copy()
        esmXDR = decodeESM(xdr1,raw[pos:pos+len1+2])
        # reference 3GPP 24.301, 8 Message functional definitions and contents
        totalLen = len(raw)
        pos += len1+2
        i = pos
        gutiType = 0
        i= pos
        count = 0
        totalLen = len(raw)
        while i < totalLen and count < 3:
            ieiByte = struct.unpack('!B',raw[i:i+1])[0]
            half = ieiByte & (((1<<4)-1)<<4)
            i += 1
            if ieiByte == 0x13:
                xdr['lac'] = struct.unpack('!H',raw[i+3:i+5])[0]
                i += 6 - 1
                count += 1
            elif ieiByte == 0x23:
                ieiLen = struct.unpack('!B',raw[i:i+1])[0]
                xdr['tmsi'] = struct.unpack('!I',raw[i+2:i+6])[0]
                i += ieiLen + 1
                count += 1
            elif ieiByte == 0x50:
                ieiLen = struct.unpack('!B',raw[i:i+1])[0]
                i += 1
                mmeGroupID,mmeCode,MTMSI = struct.unpack('!HBI',raw[i+4:i+11])
                xdr['guti'] = (mmeGroupID,mmeCode,MTMSI)
                i += ieiLen
                count += 1
            elif ieiByte == 0x5C: 
                i += 2
            elif ieiByte == 0x19: 
                i += 3
            elif ieiByte in (0x13,0x52): 
                i += 5
            elif half == 0xF0:
                pass
            else:
                ieiLen = struct.unpack('!B',raw[i:i+1])[0]
                i += ieiLen + 1
    elif xdr['msgType'] == 207:
        print(xdr['display'],xdr['msgType'],'ATTACH_COMPLETE')
        pos += 1
        len1 = struct.unpack('!H',raw[pos:pos+2])[0]
        xdr1 = xdr.copy()
        esmXDR = decodeESM(xdr1,raw[pos:pos+len1+2])
    elif xdr['msgType'] == 208:
        print(xdr['display'],xdr['msgType'],'ATTACH_REJECT')
        pos += 1
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 209:
        print(xdr['display'],xdr['msgType'],'ATTACH_REQUEST')
        xdr['EPSAttachType'] = struct.unpack('!B',raw[pos+1:pos+2])[0] & 7
        pos += 2
        len1 = struct.unpack(r'!B',raw[pos:pos+1])[0]
        type1 = struct.unpack(r'!B',raw[pos+1:pos+2])[0]
        if type1 & 7 == 1:                  # 1: imsi
            odd = 1 - (type1 >> 3) & 1
            string = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+1+len1]])
            xdr['imsi'] = string[1:len(string)-odd]
        elif type1 & 7 == 6:                # guti
            mcc,mnc,mmeGroupID,mmeCode,MTMSI = struct.unpack(r'!HBHBI',raw[pos+2:pos+1+len1])
            xdr['guti'] = (mmeGroupID,mmeCode,MTMSI)
        elif type1 & 7 == 3:                # imei
            odd = 1 - (type1 >> 3) & 1
            string = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+1+len1]])
            xdr['IMEI'] = string[1:len(string)-odd]
        pos += len1+1
        len1 = struct.unpack('!B',raw[pos:pos+1])[0]
        pos += len1+1
        len1 = struct.unpack('!H',raw[pos:pos+2])[0]
        xdr1 = xdr.copy()
        esmXDR = decodeESM(xdr1,raw[pos:pos+len1+2])
        pos += len1+2
        gutiType = 0
        i= pos
        count = 0
        totalLen = len(raw)
        while i < totalLen and count < 2:
            ieiByte = struct.unpack('!B',raw[i:i+1])[0]
            half = ieiByte & (((1<<4)-1)<<4)
            i += 1
            if ieiByte == 0x5C: 
                i += 3
            elif ieiByte == 0x50:
                ieiLen = struct.unpack('!B',raw[i:i+1])[0]
                i += 1
                mmeGroupID,mmeCode,MTMSI = struct.unpack('!HBI',raw[i+4:i+11])
                xdr['guti'] = (mmeGroupID,mmeCode,MTMSI)
                i += ieiLen + 1
                count += 1
            elif ieiByte == 0x19: 
                i += 4
            elif ieiByte in (0x13,0x52): 
                i += 6
            elif half in (0x90,0xD0,0xC0,0xF0):
                pass
            elif half == 0xE0:
                gutiType = ieiByte & 1
                count += 1
                if ieiByte & 1 == 0 and (type1 & 7) == 6:
                    xdr['guti'] = (mmeGroupID,mmeCode,MTMSI)
            else:
                ieiLen = struct.unpack('!B',raw[i:i+1])[0]
                i += ieiLen + 1
    elif xdr['msgType'] == 210:
        print(xdr['display'],xdr['msgType'],'AUTH_FAILURE')
        pass
    elif xdr['msgType'] == 211:
        print(xdr['display'],xdr['msgType'],'AUTH_REJECT')
        pass
    elif xdr['msgType'] == 212:
        print(xdr['display'],xdr['msgType'],'AUTH_REQUEST')
        xdr['rand'] = base64.b16encode(raw[pos+2:pos+18])
        xdr['imsi'] = status.randIMSI.get(xdr['rand'],'0')     # tttt
        if xdr['imsi'] != '0': del status.randIMSI[xdr['rand']]
    elif xdr['msgType'] == 213:
        print(xdr['display'],xdr['msgType'],'AUTH_RESPONSE')
        pass
    elif xdr['msgType'] == 218:
        print(xdr['display'],xdr['msgType'],'CS_SERVICE_NOTIFICATION')
        pass
    elif xdr['msgType'] == 221:
        print(xdr['display'],xdr['msgType'],'DETACH_ACCEPT')
        pass
    elif xdr['msgType'] == 222:
        print(xdr['display'],xdr['msgType'],'DETACH_REQUEST')
        pass
    elif xdr['msgType'] == 223:
        print(xdr['display'],xdr['msgType'],'EMM_INFORMATION')
        pass
    elif xdr['msgType'] == 224:
        print(xdr['display'],xdr['msgType'],'EMM_STSTUS')
        pass
    elif xdr['msgType'] == 228:
        temp_byte = raw[pos+1]
        NAS_key_set_id = (temp_byte >> 4) & 7
        Service_type = temp_byte & 15

        # 0-0    MO-CSFB    "Mobile originating CS fallback or 1xCS fallback"
        # 1-1    MT-CSFB    "Mobile terminating CS fallback or 1xCS fallback"
        # 2-2    MO-CSFB-E  "Mobile originating CS fallback emergency call or 1xCS fallback emergency call"
        # 3-4    MO-CSFB    "Mobile originating CS fallback or 1xCS fallback"
        # 8-11   PSviaS1    "Packet services via S1"
        if(Service_type == 0):
            xdr['ESR_CSFB'] = 'MO-CSFB'
        elif(Service_type == 1):
            xdr['ESR_CSFB'] = 'MT-CSFB'
        elif(Service_type == 2):
            xdr['ESR_CSFB'] = 'MT-CSFB-E'
        elif(Service_type in (3,4)):
            xdr['ESR_CSFB'] = 'MO-CSFB'
        # elif(Service_type >= 8 and Service_type <= 11):
        #     xdr['ESR_CSFB'] = 'PSviaS1'
        if xdr['ESR_CSFB'] != '':
            print(xdr['display'],xdr['msgType'],'EXTENDED_SERVICE_REQUEST('+xdr['ESR_CSFB']+')')
            xdr['keyword1'] = 'EXTENDED_SERVICE_REQUEST('+xdr['ESR_CSFB']+')'
        else:
            print(xdr['display'],xdr['msgType'],'EXTENDED_SERVICE_REQUEST')
    elif xdr['msgType'] == 229:
        print(xdr['display'],xdr['msgType'],'GUTI_REALLOCATION_COMMAND')
        pass
    elif xdr['msgType'] == 230:
        print(xdr['display'],xdr['msgType'],'GUTI_REALLOCATION_COMPLETE')
        pass
    elif xdr['msgType'] == 231:
        print(xdr['display'],xdr['msgType'],'IDENTITY_REQUEST')
        pass
    elif xdr['msgType'] == 232:
        print(xdr['display'],xdr['msgType'],'IDENTITY_RESPONSE')
        pos += 1
        len1 = struct.unpack('!B',raw[pos:pos+1])[0]
        pos += 1
        nextByte = struct.unpack('!B',raw[pos:pos+1])[0]
        odd = 2 - ((nextByte>>3)&1)
        mobile_id_type = nextByte & 7
        value = '{:X}'.format(nextByte>>4) + "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:]]) + 'F'
        # ETSI TS 124 008 V6.8.0 (2005-03) p326
        # 0, "No Identity"
        # 1, "IMSI"
        # 2, "IMEI"
        # 3, "IMEISV"
        # 4, "TMSI/P-TMSI/M-TMSI"
        # 5, "TMGI and optional MBMS Session Identity"
        if(mobile_id_type == 1):
            imsi = value
            xdr['imsi'] = imsi[:-odd]         
        elif(mobile_id_type == 2):
            imei = value
            xdr['imei'] = imei[:-odd]         
        elif(mobile_id_type == 3):
            imeisv = value
            xdr['imeisv'] = imeisv[:-odd] 
        elif(mobile_id_type == 4):
            tmsi = value
            xdr['tmsi'] = tmsi[:-odd]         
        elif(mobile_id_type == 5):
            tmgi = value
            xdr['tmgi'] = tmgi[:-odd]         
    elif xdr['msgType'] == 241:
        print(xdr['display'],xdr['msgType'],'SECURITY_MODE_COMMAND')
        pass
    elif xdr['msgType'] == 242:
        print(xdr['display'],xdr['msgType'],'SECURITY_MODE_COMPLETE')
        pass
    elif xdr['msgType'] == 243:
        print(xdr['display'],xdr['msgType'],'SECURITY_MODE_REJECT')
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 244:
        print(xdr['display'],xdr['msgType'],'SERVICE_REJECT')
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 246:
        print(xdr['display'],xdr['msgType'],'TAU_ACCEPT')
        pos += 1
        TAUType,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 7, pos + 1
        i = pos
        count = 0
        totalLen = len(raw)
        while i < totalLen and count < 1:
            ieiByte,i = struct.unpack('!B',raw[i:i+1])[0], i + 1
            half = ieiByte & (((1<<4)-1)<<4)
            if ieiByte == 0x13:
                i += 6 - 1
            elif ieiByte in (0x5A,0x53,0x17,0x59): 
                i += 2 - 1
            elif ieiByte == 0x50:
                ieiLen,i = struct.unpack('!B',raw[i:i+1])[0], i + 1
                type1,i = struct.unpack(r'!B',raw[i:i+1])[0], i + 1
                if type1 & 7 == 1:                  # 1: imsi
                    odd = 1 - (type1 >> 3) & 1
                    string = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[i:i+ieiLen]])
                    xdr['imsi'] = string[1:len(string)-odd]
                elif type1 & 7 == 6:                # guti
                    mcc,mnc,mmeGroupID,mmeCode,MTMSI = struct.unpack(r'!HBHBI',raw[i:i+ieiLen-1])
                    xdr['guti'] = (mmeGroupID,mmeCode,MTMSI)
                elif type1 & 7 == 3:                # IMEI
                    odd = 1 - (type1 >> 3) & 1
                    string = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[i:i+ieiLen]])
                    xdr['IMEI'] = string[1:len(string)-odd]
                i += ieiLen - 1
                count += 1
            elif half in (0xF0,):
                pass
            else:
                ieiLen = struct.unpack('!B',raw[i:i+1])[0]
                i += ieiLen + 1
    elif xdr['msgType'] == 247:
        print(xdr['display'],xdr['msgType'],'TAU_COMPLETE')
        pass
    elif xdr['msgType'] == 248:
        print(xdr['display'],xdr['msgType'],'TAU_REJECT')
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 249:
        print(xdr['display'],xdr['msgType'],'TAU_REQUEST')
        pos += 1
        epsUpdateType = struct.unpack('!B',raw[pos:pos+1])[0] & 7
        pos += 1
        len1 = struct.unpack('!B',raw[pos:pos+1])[0]
        pos += 1
        type1 = struct.unpack(r'!B',raw[pos:pos+1])[0]
        if type1 & 7 == 1:                  # 1: imsi
            odd = 1 - (type1 >> 3) & 1
            string = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos:pos+len1]])
            xdr['imsi'] = string[1:len(string)-odd]
        elif type1 & 7 == 6:                # guti
            mcc,mnc,mmeGroupID,mmeCode,MTMSI = struct.unpack(r'!HBHBI',raw[pos+1:pos+len1])
            xdr['guti'] = (mmeGroupID,mmeCode,MTMSI)
        elif type1 & 7 == 3:                # IMEI
            odd = 1 - (type1 >> 3) & 1
            string = "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos:pos+len1]])
            xdr['IMEI'] = string[1:len(string)-odd]
        pos += 11
        gutiType = 0
        i= pos
        count = 0
        totalLen = len(raw)
        while i < totalLen and count < 1:
            ieiByte = struct.unpack('!B',raw[i:i+1])[0]
            half = ieiByte & (((1<<4)-1)<<4)
            i += 1
            if ieiByte == 0x19: 
                i += 3
            elif ieiByte == 0x5c: 
                i += 2
            elif ieiByte == 0x55: 
                i += 4
            elif ieiByte in (0x13,0x52): 
                i += 5
            elif half in (0x80,0xA0,0x90,0xF0,0xD0,0xC0):
                pass
            elif half == 0xE0:
                gutiType = ieiByte & 1
                count += 1
                if ieiByte & 1 == 0:
                    xdr['guti'] = (mmeGroupID,mmeCode,MTMSI)
            else:
                ieiLen = struct.unpack('!B',raw[i:i+1])[0]
                i += ieiLen + 1
    elif xdr['msgType'] == 200:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT')
        pass
    elif xdr['msgType'] == 201:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT')
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 202:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST')
        pass
    elif xdr['msgType'] == 203:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT')
        pass
    elif xdr['msgType'] == 204:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT')
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 205:
        print(xdr['display'],xdr['msgType'],'ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST')
        pass
    elif xdr['msgType'] == 214:
        print(xdr['display'],xdr['msgType'],'BEARER_RESOURCE_ALLOCATION_REJECT')
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 215:
        print(xdr['display'],xdr['msgType'],'BEARER_RESOURCE_ALLOCATION_REQUEST')
        pass
    elif xdr['msgType'] == 216:
        print(xdr['display'],xdr['msgType'],'BEARER_RESOURCE_MODIFICATION_REJECT')
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 217:
        print(xdr['display'],xdr['msgType'],'BEARER_RESOURCE_MODIFICATION_REQUEST')
        pass
    elif xdr['msgType'] == 219:
        print(xdr['display'],xdr['msgType'],'DEACTIVATE_EPS_CONTEXT_ACCEPT')
        pass
    elif xdr['msgType'] == 220:
        print(xdr['display'],xdr['msgType'],'DEACTIVATE_EPS_CONTEXT_REQUEST')
        pass
    elif xdr['msgType'] == 225:
        print(xdr['display'],xdr['msgType'],'ESM_INFORMATION_REQUEST')
        pass
    elif xdr['msgType'] == 226:
        print(xdr['display'],xdr['msgType'],'ESM_INFORMATION_RESPONSE')
        pass
    elif xdr['msgType'] == 227:
        print(xdr['display'],xdr['msgType'],'ESM_STSTUS')
        pass
    elif xdr['msgType'] == 233:
        print(xdr['display'],xdr['msgType'],'MODIFY_EPS_BEARER_CONTEXT_ACCEPT')
        pass
    elif xdr['msgType'] == 234:
        print(xdr['display'],xdr['msgType'],'MODIFY_EPS_BEARER_CONTEXT_REJECT')
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 235:
        print(xdr['display'],xdr['msgType'],'MODIFY_EPS_BEARER_CONTEXT_REQUEST')
        pass
    elif xdr['msgType'] == 236:
        print(xdr['display'],xdr['msgType'],'ESM_NOTIFICATION')
        pass
    elif xdr['msgType'] == 237:
        print(xdr['display'],xdr['msgType'],'PDN_CONNECTIVITY_REJECT')
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 238:
        print(xdr['display'],xdr['msgType'],'PDN_CONNECTIVITY_REQUEST')
        pass
    elif xdr['msgType'] == 239:
        print(xdr['display'],xdr['msgType'],'PDN_DISCONNECT_REJECT')
        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
    elif xdr['msgType'] == 240:
        print(xdr['display'],xdr['msgType'],'PDN_DISCONNECT_REQUEST')
        pass
    elif xdr['msgType'] == 196:
        print(xdr['display'],xdr['msgType'],'DOWNLINK_NAS_TRANSPORT')
        pos += 1
        xdr['dir'] = '1'
        dtapLength = struct.unpack('!B',raw[pos:pos+1])[0]
        pos += 1
        if dtapLength > 0:
            nas2 = getNAS(xdr,raw[pos:pos+dtapLength])
    elif xdr['msgType'] == 197:
        print(xdr['display'],xdr['msgType'],'UPLINK_NAS_TRANSPORT')
        pos += 1
        xdr['dir'] = '0'
        dtapLength = struct.unpack('!B',raw[pos:pos+1])[0]
        pos += 1
        if dtapLength > 0:
            nas2 = getNAS(xdr,raw[pos:pos+dtapLength])
    elif xdr['msgType'] == 198:
        print(xdr['display'],xdr['msgType'],'DOWNLINK_GENERIC_NAS_TRANSPORT')
        pass
    elif xdr['msgType'] == 199:
        print(xdr['display'],xdr['msgType'],'UPLINK_GENERIC_NAS_TRANSPORT')
        pass
    elif xdr['msgType'] == 245:
        pass
    else:
        print(xdr['display'],xdr['msgType'],'Unknown NAS Message')
        return [None,esmXDR]

    if xdr['guti'] != 0 and xdr['sessionID'] != 0:
        gutiSessionID[xdr['guti']] = xdr['sessionID']
        
    if xdr['imsi'] != '0':
        sessionIMSI[xdr['sessionID']] = xdr['imsi']

    return [xdr,esmXDR]

def decodeS1AP(xdr,raw,flush):
    global errorNum,maxSessionID
    # There are too many "error indication" messages in the traffic, they do not hurt the network.
    # So we just skip them.
    if raw[1:2] == b'\x0f':  # error indication
        print(xdr['display'],'ERROR_INDICATION')
        errorNum += 1
        return
    if raw[:2] == b'\x00%':   # ignore packet of type b'0025', in future also ignore b'0028',b'0029',
        print('ignore',xdr['id'])
        return
    xdr['display'] += ', S1AP'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','4'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''

    xdr['msgType'] = s1apDict.get(base64.b16encode(raw[0:2]),0)
    xdr['guti'] = 0
    xdr['sessionID'] = 0
    xdr['ESR_CSFB'] = ''
    xdr['keyword1'] = ''

    # 0,8,16,24,26,30,88,95,96,99,100,134,43
    # 0:    mmeueid
    # 8:    enbueid
    # 16:   
    # 24:   
    # 26:   
    # 30:   
    # 43:   
    # 88:   mmeueid
    # 95:   teid
    # 96:   stmsi
    # 99:   include mmeueid and enbueid
    # 100:  
    # 134:  Cause
    try:
        IEs = getByS1APCode(raw,[0,8,16,24,26,30,88,95,96,99,100,134,43])
    except:
        IEs = {}
    xdr['mmeueid'] = IEs.get(0,-1)
    xdr['enbueid'] = IEs.get(8,'')
    if xdr['mmeueid'] == -1:
        xdr['mmeueid'] = IEs.get(88,-1)
    temp_s1apid= IEs.get(99,0)
    if temp_s1apid != 0:
        xdr['mmeueid'] = temp_s1apid[0]
        xdr['enbueid'] = temp_s1apid[1]
    xdr['stmsi'] = IEs.get(96,0)
    xdr['cgi'] = IEs.get(100,0)
    xdr['Cause'] = IEs.get(134,'')
    xdr['teid'] = IEs.get(95,0)

    if xdr['msgType'] in [250,253,256,258,260,261,263,265,268,269,272,273,274,276,277,278,279,282,283,288,293,295,296,298,300,301,302,395]:
        xdr['dir'] = '0'
        xdr['eNB_ip'] = struct.unpack('!I',xdr['sip'][0])[0]
        xdr['MME_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
    else:
        xdr['dir'] = '1'
        xdr['eNB_ip'] = struct.unpack('!I',xdr['dip'][0])[0]
        xdr['MME_ip'] = struct.unpack('!I',xdr['sip'][0])[0]

    xdrs = [xdr]

    nas1 = IEs.get(16,([],None))
    for n in nas1[0]:
        xdr1 = xdr.copy()
        nasXDR1,esmXDR1 = decodeNAS(xdr1,n)
        if nasXDR1 != None:
            xdrs.append(nasXDR1)
        if esmXDR1 != None:
            xdrs.append(esmXDR1)
    nas2 = IEs.get(24,([],None))
    for n in nas2[0]:
        xdr2 = xdr.copy()
        nasXDR2,esmXDR2 = decodeNAS(xdr2,n)
        if nasXDR2 != None:
            xdrs.append(nasXDR2)
        if esmXDR2 != None:
            xdrs.append(esmXDR2)
    if nas2[1] != None:
        if nas2[1][2] != 0:
            xdr['imsi'] = nas2[1][2]
        else:
            xdr['imsi'] = status.teidIMSI.get(nas2[1],'0')
    nas3 = IEs.get(26,[])
    for n in nas3:
        xdr3 = xdr.copy()
        nasXDR3,esmXDR3 = decodeNAS(xdr3,n)
        if nasXDR3 != None:
            xdrs.append(nasXDR3)
        if esmXDR3 != None:
            xdrs.append(esmXDR3)
    nas4 = IEs.get(30,[])
    for n in nas4:
        xdr4 = xdr.copy()
        nasXDR4,esmXDR4 = decodeNAS(xdr4,n)
        if nasXDR4 != None:
            xdrs.append(nasXDR4)
        if esmXDR4 != None:
            xdrs.append(esmXDR4)
    if xdr['msgType'] == 0:
        print(xdr['display'],xdr['msgType'],base64.b16encode(raw[0:2]))
        return
    elif xdr['msgType'] == 250:
        print(xdr['display'],xdr['msgType'],'CELL_TRAFFIC_TRACE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 251:
        print(xdr['display'],xdr['msgType'],'DEACTIVE_TRACE')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 252:
        print(xdr['display'],xdr['msgType'],'DL_NAS_TRANSPORT')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 253:
        print(xdr['display'],xdr['msgType'],'ENB_CONFIG_UPDATE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 254:
        print(xdr['display'],xdr['msgType'],'ENB_CONFIG_UPDATE_ACK')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 255:
        print(xdr['display'],xdr['msgType'],'ENB_CONFIG_UPDATE_FAILURE')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 256:
        print(xdr['display'],xdr['msgType'],'ENB_STATUS_TRANSFER')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 257:
        print(xdr['display'],xdr['msgType'],'ERAB_MODIFY_REQUEST')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 258:
        print(xdr['display'],xdr['msgType'],'ERAB_MODIFY_RESPONSE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 259:
        print(xdr['display'],xdr['msgType'],'ERAB_RELEASE_COMMAND')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
    elif xdr['msgType'] == 260:
        print(xdr['display'],xdr['msgType'],'ERAB_RELEASE_IND')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 261:
        print(xdr['display'],xdr['msgType'],'ERAB_RELEASE_RESPONSE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
    elif xdr['msgType'] == 262:
        print(xdr['display'],xdr['msgType'],'ERAB_SETUP_REQUEST')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 263:
        print(xdr['display'],xdr['msgType'],'ERAB_SETUP_RESPONSE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 264:
        print(xdr['display'],xdr['msgType'],'ERROR_INDICATION')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 265:
        print(xdr['display'],xdr['msgType'],'HANDOVER_CANCEL')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 266:
        print(xdr['display'],xdr['msgType'],'HANDOVER_CANCEL_ACK')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 267:
        print(xdr['display'],xdr['msgType'],'HANDOVER_COMMAND')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 268:
        print(xdr['display'],xdr['msgType'],'HANDOVER_FAILURE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 269:
        print(xdr['display'],xdr['msgType'],'HANDOVER_NOTIFY')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 270:
        print(xdr['display'],xdr['msgType'],'HANDOVER_PREPARE_FAILURE')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 271:
        print(xdr['display'],xdr['msgType'],'HANDOVER_REQUEST')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 272:
        print(xdr['display'],xdr['msgType'],'HANDOVER_REQUEST_ACK')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 273:
        print(xdr['display'],xdr['msgType'],'HANDOVER_REQUIRED')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 274:
        print(xdr['display'],xdr['msgType'],'INITIAL_CONTEXT_SETUP_FAILURE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 275:
        print(xdr['display'],xdr['msgType'],'INITIAL_CONTEXT_SETUP_REQUEST')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 276:
        print(xdr['display'],xdr['msgType'],'INITIAL_CONTEXT_SETUP_RESPONSE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 277:
        print(xdr['display'],xdr['msgType'],'INITIAL_UE_MESSAGE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
        guti = 0
        stmsi = 0
        imsi = '0'
        sessionID1 = 0
        for n in xdrs:
            temp_guti = n.get('guti',0)
            temp_stmsi = n.get('stmsi',0)
            temp_imsi = n.get('imsi','0')
            if temp_guti != 0: 
                guti = temp_guti
                stmsi = (guti[1],guti[2])
            if temp_stmsi != 0: stmsi = temp_stmsi
            if temp_imsi != '0': imsi = temp_imsi
        if imsi != '0':
            xdr['imsi'] = imsi
            sessionID1 = imsiSessionID.get(imsi,0)
        
        if sessionID1 == 0 and guti != 0:
            xdr['guti'] = guti
            sessionID1 = gutiSessionID.get(guti,0)

        if sessionID1 == 0 and stmsi != 0:
            xdr['stmsi'] = stmsi
            sessionID1 = pagingSessionID.get(stmsi,0)
        
        if sessionID1 == 0:
            maxSessionID += 1
            sessionID1 = maxSessionID
            if imsi != '0':   imsiSessionID[imsi] = sessionID1
            if guti != 0:   gutiSessionID[guti] = sessionID1
            if stmsi != 0:  pagingSessionID[stmsi] = sessionID1
        s1apHalfSessionID[(xdr['enbIP'] , xdr['enbueid'])] = sessionID1
        xdr['sessionID'] = sessionID1
        if stmsi != 0:
            pages = pagingList.get(stmsi,0)
            if pages != 0:
                pagingAck = None
                foundPagingPair = False
                ts = 0
                tsList = []
                for page in pages:
                    if page.get('dip')[0] == xdr.get('sip')[0]:
                        pagingAck = page
                        foundPagingPair = True
                        pagingAck['sessionID'] = xdr['sessionID']
                        pagingAck['imsi'] = xdr['imsi']
                        ts = pagingAck['ts']
                    tsList.append(page['ts'][0]*1000000000+page['ts'][1])
                if foundPagingPair == False:
                    pagingAck = pages[0]
                    pagingAck['sessionID'] = xdr['sessionID']
                    pagingAck['imsi'] = xdr['imsi']
                    ts = pagingAck['ts']
                tsList = sorted(tsList)
                count = 0
                ts1 = tsList[0]
                for timeStamp in tsList[1:]:
                    if timeStamp - ts1 > 500000000:
                        count += 1
                    ts1 = timeStamp
                pagingAck['Retrs'] = count
                temp1 = ts[0]*1000000000+ts[1]
                temp2 = xdr['ts'][0]*1000000000+xdr['ts'][1]
                pagingAck['Latency'] = (temp2 - temp1)//1000000
                cacheS1APXDR(pagingAck)                
                del pagingList[stmsi]
            else:
                pass
        for n in xdrs[1:]:
            n['sessionID'] = xdr['sessionID']
            n['imsi'] = xdr['imsi']
            cacheNASXDR(n)
        cacheS1APXDR(xdr)
        del xdrs
        return
    elif xdr['msgType'] == 278:
        print(xdr['display'],xdr['msgType'],'LOCATION_REPORT')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 279:
        print(xdr['display'],xdr['msgType'],'LOCATION_REPORT_FAILURE_IND')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 280:
        print(xdr['display'],xdr['msgType'],'LOCATION_REPORTING_CONTROL')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 281:
        print(xdr['display'],xdr['msgType'],'MME_CONFIG_UPDATE')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 282:
        print(xdr['display'],xdr['msgType'],'MME_CONFIG_UPDATE_ACK')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 283:
        print(xdr['display'],xdr['msgType'],'MME_CONFIG_UPDATE_FAILURE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 284:
        print(xdr['display'],xdr['msgType'],'MME_STATUS_TRANSFER')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 285:
        print(xdr['display'],xdr['msgType'],'OVERLOAD_START')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 286:
        print(xdr['display'],xdr['msgType'],'OVERLOAD_STOP')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 287:
        print(xdr['display'],xdr['msgType'],'PAGING')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
        pagingID = IEs.get(43,0)

        if pagingID == 0:
            print('error pagingID should not be zero')
        else:
            paging_result = paging_dict.get(pagingID,None)
            if(paging_result != None):
                del xdr
            else:
                paging_dict[pagingID] = True

                if pagingID[0] == 0:
                    xdr['pagingID'] = pagingID[1:3]
                    xdr['sessionID'] = pagingSessionID.get(xdr['pagingID'],0)
                    temp = pagingList.get(xdr['pagingID'],0)
                    if temp == 0:
                        temp = [xdr]
                        pagingList[pagingID[1:3]] = temp
                    else:
                        pagingList[pagingID[1:3]].append(xdr)
                else:
                    xdr['imsi'] = pagingID[1]
                    if xdr.get('sessionID',0) != 0:
                        sessionIMSI[xdr['sessionID']] = xdr['imsi']
        return
    elif xdr['msgType'] == 288:
        print(xdr['display'],xdr['msgType'],'PATH_SWITCH_REQUEST')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
        sessionID1 = pathSessionID.get(xdr['mmeueid'],-1)
        if sessionID1 != 0:
            xdr['sessionID'] = sessionID1
            pathSessionID[xdr['mmeueid']] = sessionID1
            s1apSessionID[(xdr['mmeueid'] , xdr['enbIP'] , xdr['enbueid'])] = sessionID1
            s1apHalfSessionID[(xdr['enbIP'] , xdr['enbueid'])] = sessionID1
            xdr['imsi'] = sessionIMSI.get(xdr['sessionID'],'0')
            cacheS1APXDR(xdr)
        else:
            pathSwitchReqList[(xdr['mmeueid'] , xdr['enbIP'] , xdr['enbueid'])] = xdr
            sessionID1 = teidSessionID.get(xdr['teid'],0)
            if sessionID1 == 0:
                maxSessionID += 1
                sessionID1 = maxSessionID 
            xdr['sessionID'] = sessionID1
            cacheS1APXDR(xdr)
        return
    elif xdr['msgType'] == 289:
        print(xdr['display'],xdr['msgType'],'PATH_SWITCH_REQUEST_ACK')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
        sessionID1 = 0
        context = (xdr['mmeueid'],xdr['enbIP'],xdr['enbueid'])
        sessionID1 = s1apSessionID.get(context,0)
        if sessionID1 == 0:
            sessionID1 = teidSessionID.get(xdr['teid'],0)
            if sessionID1 == 0:
                maxSessionID += 1
                sessionID1 = maxSessionID 
        xdr['sessionID'] = sessionID1
        teidSessionID[xdr['teid']] = xdr['sessionID']      
        s1apSessionID[(xdr['mmeueid'] , xdr['enbIP'] , xdr['enbueid'])] = sessionID1
        pathSessionID[xdr['mmeueid']] = sessionID1
        xdr['imsi'] = sessionIMSI.get(xdr['sessionID'],'0')
        
        xdr1 = pathSwitchReqList.get(context,0)
        if xdr1 != 0:
            xdr1['sessionID'] = xdr['sessionID']
            cacheS1APXDR(xdr1)
        cacheS1APXDR(xdr)
        return
    elif xdr['msgType'] == 290:
        print(xdr['display'],xdr['msgType'],'PATH_SWITCH_REQUEST_FAILURE')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 291:
        print(xdr['display'],xdr['msgType'],'RESET')
        if xdr['sip'] in s1apMMEIP:
            xdr['enbIP'] = xdr['dip'][0]
            xdr['mmeIP'] = xdr['sip'][0]
            xdr['dir'] = '1'
        elif xdr['dip'] in s1apMMEIP:
            xdr['enbIP'] = xdr['sip'][0]
            xdr['mmeIP'] = xdr['dip'][0]
            xdr['dir'] = '0'
        else:
            xdr['enbIP'] = xdr['dip'][0]
            xdr['mmeIP'] = xdr['sip'][0]
            xdr['dir'] = '1'
    elif xdr['msgType'] == 292:
        print(xdr['display'],xdr['msgType'],'RESET_ACK')
        if xdr['sip'] in s1apMMEIP:
            xdr['enbIP'] = xdr['dip'][0]
            xdr['mmeIP'] = xdr['sip'][0]
            xdr['dir'] = '1'
        elif xdr['dip'] in s1apMMEIP:
            xdr['enbIP'] = xdr['sip'][0]
            xdr['mmeIP'] = xdr['dip'][0]
            xdr['dir'] = '0'
        else:
            xdr['enbIP'] = xdr['sip'][0]
            xdr['mmeIP'] = xdr['dip'][0]
            xdr['dir'] = '0'
    elif xdr['msgType'] == 293:
        print(xdr['display'],xdr['msgType'],'TRACE_FAILURE_IND')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 294:
        print(xdr['display'],xdr['msgType'],'TRACE_START')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 295:
        print(xdr['display'],xdr['msgType'],'UE_CAPABILITY_INFO_IND')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 296:
        print(xdr['display'],xdr['msgType'],'UE_CONTEXT_MODIFICATION_FAILURE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 297:
        print(xdr['display'],xdr['msgType'],'UE_CONTEXT_MODIFICATION_REQUEST')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 298:
        print(xdr['display'],xdr['msgType'],'UE_CONTEXT_MODIFICATION_RESPONSE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 299:
        print(xdr['display'],xdr['msgType'],'UE_CONTEXT_RELEASE_COMMAND')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 300:
        print(xdr['display'],xdr['msgType'],'UE_CONTEXT_RELEASE_COMPLETE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 301:
        print(xdr['display'],xdr['msgType'],'UE_CONTEXT_RELEASE_REQUEST')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 302:
        print(xdr['display'],xdr['msgType'],'UL_NAS_TRANSPORT')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 395:
        print(xdr['display'],xdr['msgType'],'S1_SETUP_REQUEST')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
    elif xdr['msgType'] == 396:
        print(xdr['display'],xdr['msgType'],'S1_SETUP_RESPONSE')
        xdr['enbIP'] = xdr['sip'][0]
        xdr['mmeIP'] = xdr['dip'][0]
        xdr['dir'] = '0'
    elif xdr['msgType'] == 397:
        print(xdr['display'],xdr['msgType'],'S1_SETUP_FAILURE')
        xdr['enbIP'] = xdr['dip'][0]
        xdr['mmeIP'] = xdr['sip'][0]
        xdr['dir'] = '1'
        outputS1APXDR(xdr)
        return
    else:
        if base64.b16encode(raw[0:2]) in (b'0025',b'0028',b'0029'):
            pass
        else:
            print(xdr['display'],base64.b16encode(raw[0:2]),' unknown')

    if xdr['dir'] == '0':
        if xdr['dip'] not in s1apMMEIP and xdr['msgType'] not in [291,292]: s1apMMEIP.append(xdr['dip'])
    else:
        if xdr['sip'] not in s1apMMEIP and xdr['msgType'] not in [291,292]: s1apMMEIP.append(xdr['sip'])
    
    guti = 0
    stmsi = 0
    imsi = '0'
    for n in xdrs:
        temp_guti = n.get('guti',0)
        temp_stmsi = n.get('stmsi',0)
        temp_imsi = n.get('imsi','0')
        if temp_guti != 0: 
            guti = temp_guti
            stmsi = (guti[1],guti[2])
        if temp_stmsi != 0: stmsi = temp_stmsi
        if temp_imsi != '0': imsi = temp_imsi
    xdr['guti'] = guti
    xdr['stmsi'] = stmsi
    xdr['imsi'] = imsi
    sessionID1 = 0
    
    if xdr['mmeueid'] != -1:
        context = (xdr['mmeueid'],xdr['enbIP'],xdr['enbueid'])
        halfContext = (xdr['enbIP'],xdr['enbueid'])
        sessionID1 = s1apSessionID.get(context,0)
        if sessionID1 == 0:
            sessionID1 = s1apHalfSessionID.get(halfContext,0)
            if sessionID1 == 0:
                maxSessionID += 1
                sessionID1 = maxSessionID
            else:
                del s1apHalfSessionID[halfContext]
    else:
        if xdr['msgType'] == 264:
            pass
        else:
            print('Error S1AP others msg does not have mmeUEID',xdr['msgType'])
    
    if xdr['imsi'] != '0': sessionIMSI[sessionID1] = xdr['imsi']
    
    xdr['sessionID'] = sessionID1
    s1apSessionID[(xdr['mmeueid'] , xdr['enbIP'] , xdr['enbueid'])] = sessionID1
    pathSessionID[xdr['mmeueid']] = sessionID1
    if xdr['guti'] != 0:
        gutiSessionID[xdr['guti']] = sessionID1
        pagingSessionID[(xdr['guti'][1],xdr['guti'][2])] = sessionID1

    imsi = sessionIMSI.get(xdr['sessionID'],'0')

    if imsi != '0':  xdr['imsi'] = imsi

    for n in xdrs[1:]:
        n['sessionID'] = xdr['sessionID']
        n['imsi'] = xdr['imsi']
        cacheNASXDR(n)
    del xdrs
    cacheS1APXDR(xdr)
    del xdr

def outputS1APXDR(xdr):
    global s1apOutputFile
    if xdr['imsi'] == '0': xdr['imsi'] = str(888884000000000+xdr['sessionID'])
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'S1'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr['enbueid']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if s1apOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        s1apOutputFileName = os.path.join(status.sdlDirectory, 'LteCP_s1_Msg_'+b+'.tmp')
        s1apOutputFile = open(s1apOutputFileName,'w')
        if s1apOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(s1apOutputFile)
    s1apOutputFile.writelines(string)
    return
def cacheS1APXDR(xdr):
    sessionID = xdr.get('sessionID',0)
    if sessionID == 0:
        print('Error, xdr without sessionID, packet id=',xdr['id'])
        return
    imsi = xdr.get('imsi','0')
    if imsi != '0':
        for i in range(len(s1apXDR)-1,-1,-1):
            if s1apXDR[i]['sessionID'] == sessionID:
                s1apXDR[i]['imsi'] = imsi
                outputS1APXDR(s1apXDR[i])
                s1apXDR.remove(s1apXDR[i])
        outputS1APXDR(xdr)
    else:
        s1apXDR.append(xdr)
    cacheS1APNASCPlatency(xdr)
    return
def flushS1APXDR():
    global s1apCPLatency1OutputFile,s1apCPLatency2OutputFile,s1apCPLatency3OutputFile,s1apCPLatency4OutputFile,s1apCPLatency5OutputFile
    for n in s1apXDR:
        imsi = sessionIMSI.get(n['sessionID'],'0')
        if imsi != '0': n['imsi'] = imsi
        outputS1APXDR(n)
    s1apXDR.clear()
    for n in pagingList:
        for m in pagingList[n]:
            outputS1APXDR(m)
    pagingList.clear()
    return

def outputNASXDR(xdr):
    global nasOutputFile,nasCPLatency1OutputFile,nasCPLatency2OutputFile,nasCPLatency3OutputFile,nasCPLatency4OutputFile,nasCPLatency5OutputFile
    if xdr['msgType'] != 287:
        if xdr['imsi'] == '0': xdr['imsi'] = str(888884000000000+xdr['sessionID'])
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
        ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
        if len(xdr['sip'][-1]) == 4:
            sip = inet_ntoa(xdr['sip'][-1])
            dip = inet_ntoa(xdr['dip'][-1])
        elif len(xdr['sip'][-1]) == 16:
            sip = inet_ntop(AF_INET6, xdr['sip'][-1])
            dip = inet_ntop(AF_INET6, xdr['dip'][-1])
        xdr['interface'] = 'NAS'
        if(xdr['imsi'] == '0'): xdr['imsi'] = ''
        if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
        status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['keyword1'],'','','',str(xdr['enbueid']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

        if nasOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            nasOutputFileName = os.path.join(status.sdlDirectory, 'LteCP_nas_Msg_'+b+'.tmp')
            nasOutputFile = open(nasOutputFileName,'w')
            if nasOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(nasOutputFile)
        nasOutputFile.writelines(string)
    return
def cacheNASXDR(xdr):
    sessionID = xdr.get('sessionID',0)
    if sessionID == 0:
        print('Error, xdr without sessionID, packet id=',xdr['id'])
        return
    imsi = xdr.get('imsi','0')
    if imsi != '0':
        for i in range(len(nasXDR)-1,-1,-1):
            if nasXDR[i]['sessionID'] == sessionID:
                nasXDR[i]['imsi'] = imsi
                outputNASXDR(nasXDR[i])
                nasXDR.remove(nasXDR[i])
        outputNASXDR(xdr)
    else:
        nasXDR.append(xdr)
    cacheS1APNASCPlatency(xdr)
    return
def flushNASXDR():
    global nasCPLatencyOutputFile,nasCPLatency1OutputFile,nasCPLatency2OutputFile,nasCPLatency3OutputFile,nasCPLatency4OutputFile,nasCPLatency5OutputFile
    
    for n in nasXDR:
        imsi = sessionIMSI.get(n['sessionID'],'0')
        if imsi != '0':
            n['imsi'] = imsi
        outputNASXDR(n)
    nasXDR.clear()
    return

def cacheS1APNASCPlatency(xdr):
    global CPlatencyXDR,s1apCPLatency1OutputFile,s1apCPLatency2OutputFile,s1apCPLatency3OutputFile,nasCPLatency1OutputFile,nasCPLatency2OutputFile,nasCPLatency3OutputFile,nasCPLatency4OutputFile,nasCPLatency5OutputFile
    if xdr['msgType'] in (209,206,212,222,222,229,231,241,245,228,249,246,205,202,215,217,220,235,238,240,273,271,288,265,262,257,259,275,291,395,299,297,253):
        temp = s1apnasCPLatency.get((xdr['enbueid'],xdr['mmeueid'],xdr['msgType']),0)
        if temp == 0:
            s1apnasCPLatency[(xdr['enbueid'],xdr['mmeueid'],xdr['msgType'])] = [xdr]
        else:
            s1apnasCPLatency[(xdr['enbueid'],xdr['mmeueid'],xdr['msgType'])].append(xdr)
    outputXDRs = []
    if xdr['msgType'] == 287:
        xdr['prcType'] = 1020
        xdr['SuccFlag'] = 0
        xdr['APN_Id'] = ''
        xdr['msisdn'] = ''
        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['Timeout'] = ''
        xdr['Cause'] = ''
        xdr['pt_tsn'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600
        xdr['cgi'] = xdr['cgi']
        xdr['Network'] = xdr['Network']
        xdr['eNB_id'] = ''      #s1apnasCPLatency[xdr][0]['eNB_id']
        xdr['xType'] = ''       #s1apnasCPLatency[xdr][0]['xType']
        xdr['eNB_ip'] = xdr['eNB_ip']
        xdr['MME_ip'] = xdr['MME_ip']
        xdr['sessionID'] = xdr['sessionID']
        xdr['msgType'] = xdr['msgType']
        imsi = sessionIMSI.get(xdr['sessionID'],'0')
        xdr['imsi'] = imsi
        if xdr['imsi'] != '0':
            outputXDRs.append(xdr)
        else:
            CPlatencyXDR.append(xdr)
    if 1 in s1apnasPair.keys():
        for n in s1apnasPair[1]:
            tempxdr = {}
            if xdr['msgType'] not in (244,245,228,277,287):
                temp = s1apnasCPLatency.get((xdr['enbueid'],xdr['mmeueid'],n[0]),0)
                mmeueid = 1
                if temp == 0:
                    temp = s1apnasCPLatency.get((xdr['enbueid'],0,n[0]),0)
                    mmeueid = 0
                if temp != 0:
                    tempxdr['prcType'] = n[1]
                    tempxdr['SuccFlag'] = n[2]
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
                    if mmeueid == 0:
                        del s1apnasCPLatency[(xdr['enbueid'],0,n[0])]
                    else:
                        del s1apnasCPLatency[(xdr['enbueid'],xdr['mmeueid'],n[0])]
                    
                    tempxdr['APN_Id'] = ''
                    tempxdr['msisdn'] = ''
                    tempxdr['tid'] = ''
                    tempxdr['tac'] = ''
                    tempxdr['Timeout'] = ''
                    tempxdr['eNB_id'] = ''
                    tempxdr['Cause'] = xdr['Cause']
                    tempxdr['pt_tsn'] = (tempxdr['ts'][0]-time.timezone) % 86400 // 3600
                    tempxdr['cgi'] = xdr['cgi']
                    tempxdr['Network'] = xdr['Network']
                    tempxdr['eNB_id'] = ''      #s1apnasCPLatency[xdr][0]['eNB_id']
                    tempxdr['xType'] = ''       #s1apnasCPLatency[xdr][0]['xType']
                    tempxdr['eNB_ip'] = xdr['eNB_ip']
                    tempxdr['MME_ip'] = xdr['MME_ip']
                    tempxdr['sessionID'] = xdr['sessionID']
                    tempxdr['msgType'] = xdr['msgType']
                    imsi = sessionIMSI.get(tempxdr['sessionID'],'0')
                    if imsi != '0':
                        tempxdr['imsi'] = imsi
                        outputXDRs.append(tempxdr)
                    else:
                        CPlatencyXDR.append(tempxdr)
    if xdr['msgType'] in s1apnasPair.keys() and xdr['msgType'] != 287:
        for n in s1apnasPair[xdr['msgType']]:
            tempxdr = {}
            temp = s1apnasCPLatency.get((xdr['enbueid'],xdr['mmeueid'],n[0]),0)
            mmeueid = 1
            if temp == 0:
                temp = s1apnasCPLatency.get((xdr['enbueid'],0,n[0]),0)
                mmeueid = 0
            if temp != 0:
                if xdr['msgType'] == 221:
                    if xdr['dir'] == '0':
                        tempxdr['prcType'] = 1004
                    else:
                        tempxdr['prcType'] = 1003
                else:
                    tempxdr['prcType'] = n[1]
                tempxdr['SuccFlag'] = n[2]
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
                if mmeueid == 0:
                    del s1apnasCPLatency[(xdr['enbueid'],0,n[0])]
                else:
                    del s1apnasCPLatency[(xdr['enbueid'],xdr['mmeueid'],n[0])]
                tempxdr['APN_Id'] = ''
                tempxdr['msisdn'] = ''
                tempxdr['tid'] = ''
                tempxdr['tac'] = ''
                tempxdr['Timeout'] = ''
                tempxdr['eNB_id'] = ''
                tempxdr['Cause'] = xdr['Cause']
                tempxdr['pt_tsn'] = (tempxdr['ts'][0]-time.timezone) % 86400 // 3600
                tempxdr['cgi'] = xdr['cgi']
                tempxdr['Network'] = xdr['Network']
                tempxdr['eNB_id'] = ''      #s1apnasCPLatency[xdr][0]['eNB_id']
                tempxdr['xType'] = ''       #s1apnasCPLatency[xdr][0]['xType']
                tempxdr['eNB_ip'] = xdr['eNB_ip']
                tempxdr['MME_ip'] = xdr['MME_ip']
                tempxdr['sessionID'] = xdr['sessionID']
                tempxdr['msgType'] = xdr['msgType']
                imsi = sessionIMSI.get(xdr['sessionID'],'0')
                if imsi != '0':
                    tempxdr['imsi'] = imsi
                    outputXDRs.append(tempxdr)
                else:
                    CPlatencyXDR.append(tempxdr)
    for xdr in outputXDRs:
        if xdr['prcType'] in (1000,1001,1002,1003,1004,1006):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency1OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency1OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_NAS_CPLatency1_'+b+'.tmp')
                nasCPLatency1OutputFile = open(nasCPLatency1OutputFileName,'w')
                if nasCPLatency1OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency1OutputFile)
            nasCPLatency1OutputFile.writelines(string)
        elif xdr['prcType'] in (1010,1011):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency2OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency2OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_NAS_CPLatency2_'+b+'.tmp')
                nasCPLatency2OutputFile = open(nasCPLatency2OutputFileName,'w')
                if nasCPLatency2OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency2OutputFile)
            nasCPLatency2OutputFile.writelines(string)
        elif xdr['prcType'] in (1099,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency3OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency3OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_NAS_CPLatency3_'+b+'.tmp')
                nasCPLatency3OutputFile = open(nasCPLatency3OutputFileName,'w')
                if nasCPLatency3OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency3OutputFile)
            nasCPLatency3OutputFile.writelines(string)
        elif xdr['prcType'] in (1005,1007,1009,1012,1013,1014,1015,1016,1017,1018,1019):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency4OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency4OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_NAS_CPLatency4_'+b+'.tmp')
                nasCPLatency4OutputFile = open(nasCPLatency4OutputFileName,'w')
                if nasCPLatency4OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency4OutputFile)
            nasCPLatency4OutputFile.writelines(string)
        elif xdr['prcType'] in (1008,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency5OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency5OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_NAS_CPLatency5_'+b+'.tmp')
                nasCPLatency5OutputFile = open(nasCPLatency5OutputFileName,'w')
                if nasCPLatency5OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency5OutputFile)
            nasCPLatency5OutputFile.writelines(string)
        if xdr['prcType'] in (1100,1101,1102,1103,1104,1105,1106,1108,1109,1111,1112,1113,1114,1115,1020):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if s1apCPLatency1OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                s1apCPLatency1OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency1_'+b+'.tmp')
                s1apCPLatency1OutputFile = open(s1apCPLatency1OutputFileName,'w')
                if s1apCPLatency1OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(s1apCPLatency1OutputFile)
            s1apCPLatency1OutputFile.writelines(string)
        elif xdr['prcType'] in (1107,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if s1apCPLatency2OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                s1apCPLatency2OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency2_'+b+'.tmp')
                s1apCPLatency2OutputFile = open(s1apCPLatency2OutputFileName,'w')
                if s1apCPLatency2OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(s1apCPLatency2OutputFile)
            s1apCPLatency2OutputFile.writelines(string)
        elif xdr['prcType'] in (1110,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if s1apCPLatency3OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                s1apCPLatency3OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency3_'+b+'.tmp')
                s1apCPLatency3OutputFile = open(s1apCPLatency3OutputFileName,'w')
                if s1apCPLatency3OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(s1apCPLatency3OutputFile)
            s1apCPLatency3OutputFile.writelines(string)
                
    return
def flushS1APNASCPlatency():
    global CPlatencyXDR,nasCPLatency1OutputFile,nasCPLatency2OutputFile,nasCPLatency3OutputFile,nasCPLatency4OutputFile,nasCPLatency5OutputFile
    global s1apCPLatency1OutputFile,s1apCPLatency2OutputFile,s1apCPLatency3OutputFile
    
    for xdr in CPlatencyXDR:
        xdr['imsi'] = sessionIMSI.get(xdr['sessionID'],'0')
    xdrs = CPlatencyXDR
    for xdr in s1apnasCPLatency:
        tempxdr = {}
        tempxdr['sessionID'] = s1apnasCPLatency[xdr][0]['sessionID']
        tempxdr['prcType'] = requestMsg[xdr[2]]
        if xdr[2] == 222:
            if s1apnasCPLatency[xdr][0]['dir'] == 0:
                tempxdr['prcType'] = 1003
            else:
                tempxdr['prcType'] = 1004
        tempxdr['SuccFlag'] = 1
        tempxdr['Retrs'] = len(s1apnasCPLatency[xdr])
        if tempxdr['Retrs'] > 0: tempxdr['Retrs'] -= 1
        ts = s1apnasCPLatency[xdr][0]['ts']
        for m in s1apnasCPLatency[xdr][1:]:
            if m['ts'][0] < ts[0]:
                ts = m['ts']
            elif m['ts'][0] > ts[0]:
                pass
            else:
                if m['ts'][1] < ts[1]:
                    ts = m['ts']
        tempxdr['Latency'] = 0
        tempxdr['ts'] = ts
        tempxdr['APN_Id'] = ''
        tempxdr['msisdn'] = ''
        tempxdr['tid'] = ''
        tempxdr['tac'] = ''
        tempxdr['Timeout'] = ''
        tempxdr['eNB_id'] = ''
        tempxdr['Cause'] = ''
        tempxdr['pt_tsn'] = s1apnasCPLatency[xdr][0]['pt_tsn']
        tempxdr['cgi'] = s1apnasCPLatency[xdr][0]['cgi']
        tempxdr['Network'] = s1apnasCPLatency[xdr][0]['Network']
        tempxdr['eNB_id'] = ''      #s1apnasCPLatency[xdr][0]['eNB_id']
        tempxdr['xType'] = ''       #s1apnasCPLatency[xdr][0]['xType']
        tempxdr['eNB_ip'] = s1apnasCPLatency[xdr][0]['eNB_ip']
        tempxdr['MME_ip'] = s1apnasCPLatency[xdr][0]['MME_ip']
        tempxdr['imsi'] = sessionIMSI.get(s1apnasCPLatency[xdr][0]['sessionID'],'0')
        CPlatencyXDR.append(tempxdr)
    s1apnasCPLatency.clear()

    for pages in pagingList:
        xdr = pagingList[pages][0]
        xdr['prcType'] = 1020
        xdr['SuccFlag'] = 1
        count = 0
        tsList = []
        for page in pagingList[pages]:
            tsList.append(page['ts'][0]*1000000000+page['ts'][0])
        tsList = sorted(tsList)
        ts1 = tsList[0]
        for timeStamp in tsList[1:]:
            if timeStamp - ts1 > 500000000:
                count += 1
            ts1 = timeStamp
        xdr['Retrs'] = str(count)
        xdr['Latency'] = ''
        xdr['APN_Id'] = ''
        xdr['msisdn'] = ''
        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['Timeout'] = ''
        xdr['Cause'] = ''
        xdr['pt_tsn'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600
        xdr['cgi'] = xdr['cgi']
        xdr['Network'] = xdr['Network']
        xdr['eNB_id'] = ''      #s1apnasCPLatency[xdr][0]['eNB_id']
        xdr['xType'] = ''       #s1apnasCPLatency[xdr][0]['xType']
        xdr['eNB_ip'] = xdr['eNB_ip']
        xdr['MME_ip'] = xdr['MME_ip']
        xdr['sessionID'] = xdr['sessionID']
        xdr['msgType'] = xdr['msgType']
        CPlatencyXDR.append(xdr)
    pagingList.clear()
    
    
    for xdr in CPlatencyXDR:
        if xdr['imsi'] == '0': xdr['imsi'] = str(888884000000000+xdr['sessionID'])
        if xdr['prcType'] in (1000,1001,1002,1003,1004,1006):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency1OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency1OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_NAS_CPLatency1_'+b+'.tmp')
                nasCPLatency1OutputFile = open(nasCPLatency1OutputFileName,'w')
                if nasCPLatency1OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency1OutputFile)
            nasCPLatency1OutputFile.writelines(string)
        elif xdr['prcType'] in (1010,1011):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency2OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency2OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_NAS_CPLatency2_'+b+'.tmp')
                nasCPLatency2OutputFile = open(nasCPLatency2OutputFileName,'w')
                if nasCPLatency2OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency2OutputFile)
            nasCPLatency2OutputFile.writelines(string)
        elif xdr['prcType'] in (1099,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency3OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency3OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_NAS_CPLatency3_'+b+'.tmp')
                nasCPLatency3OutputFile = open(nasCPLatency3OutputFileName,'w')
                if nasCPLatency3OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency3OutputFile)
            nasCPLatency3OutputFile.writelines(string)
        elif xdr['prcType'] in (1005,1007,1009,1012,1013,1014,1015,1016,1017,1018,1019):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency4OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency4OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_NAS_CPLatency4_'+b+'.tmp')
                nasCPLatency4OutputFile = open(nasCPLatency4OutputFileName,'w')
                if nasCPLatency4OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency4OutputFile)
            nasCPLatency4OutputFile.writelines(string)
        elif xdr['prcType'] in (1008,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency5OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency5OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_NAS_CPLatency5_'+b+'.tmp')
                nasCPLatency5OutputFile = open(nasCPLatency5OutputFileName,'w')
                if nasCPLatency5OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency5OutputFile)
            nasCPLatency5OutputFile.writelines(string)
        if xdr['prcType'] in (1100,1101,1102,1103,1104,1105,1106,1108,1109,1111,1112,1113,1114,1115,1020):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if s1apCPLatency1OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                s1apCPLatency1OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency1_'+b+'.tmp')
                s1apCPLatency1OutputFile = open(s1apCPLatency1OutputFileName,'w')
                if s1apCPLatency1OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(s1apCPLatency1OutputFile)
            s1apCPLatency1OutputFile.writelines(string)
        elif xdr['prcType'] in (1107,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if s1apCPLatency2OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                s1apCPLatency2OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency2_'+b+'.tmp')
                s1apCPLatency2OutputFile = open(s1apCPLatency2OutputFileName,'w')
                if s1apCPLatency2OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(s1apCPLatency2OutputFile)
            s1apCPLatency2OutputFile.writelines(string)
        elif xdr['prcType'] in (1110,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if s1apCPLatency3OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                s1apCPLatency3OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency3_'+b+'.tmp')
                s1apCPLatency3OutputFile = open(s1apCPLatency3OutputFileName,'w')
                if s1apCPLatency3OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(s1apCPLatency3OutputFile)
            s1apCPLatency3OutputFile.writelines(string)
        
    return

s1apXDR = []
nasXDR = []
errorNum = 0

paging_dict = {}

#status.enbueidDict = {}

CPlatencyXDR = []
s1apnasCPLatency = {}

sessionIMSI = {}

gutiSessionID = {}
s1apSessionID = {}
pagingSessionID = {}
s1apHalfSessionID = {}
pathSessionID = {}
teidSessionID = {}
imsiSessionID = {}

pagingList = {}
pathSwitchReqList = {}
maxSessionID = 0

s1apOutputFile = None
s1apCPLatency1OutputFile = None
s1apCPLatency2OutputFile = None
s1apCPLatency3OutputFile = None


s1apCPLatency = {}

nasOutputFile = None
nasCPLatency1OutputFile = None
nasCPLatency2OutputFile = None
nasCPLatency3OutputFile = None
nasCPLatency4OutputFile = None
nasCPLatency5OutputFile = None
nasCPLatency = {}


s1apDict = {b'4015': 296, b'0006': 257, b'001C': 293, b'2006': 258, b'0011': 395, b'000D': 302, b'000F': 264, b'002A': 250, b'201E': 282, b'0023': 286, b'2001': 272, b'4000': 270, b'401D': 255, b'001B': 294, b'0019': 284, b'001E': 281, b'4011': 397, b'200E': 292, b'0022': 285, b'0001': 271, b'001F': 280, b'0018': 256, b'000E': 291, b'0000': 273, b'0003': 288, b'4009': 274, b'0017': 299, b'0020': 279, b'001A': 251, b'000C': 277, b'0008': 260, b'2017': 300, b'2005': 263, b'000A': 287, b'0007': 259, b'0004': 265, b'2011': 396, b'0021': 278, b'000B': 252, b'4001': 268, b'0009': 275, b'0012': 301, b'0015': 297, b'2015': 298, b'401E': 283, b'0016': 295, b'0005': 262, b'2007': 261, b'2003': 289, b'2004': 266, b'0002': 269, b'4003': 290, b'201D': 254, b'2009': 276, b'2000': 267, b'001D': 253}

emmDict = {b'60': 224, b'43': 207, b'44': 208, b'4A': 247, b'54': 211, b'48': 249, b'49': 246, b'5C': 210, b'56': 232, b'45': 222, b'50': 229, b'4C': 228, b'55': 231, b'64': 218, b'46': 221, b'51': 230, b'41': 209, b'5D': 241, b'61': 223, b'5E': 242, b'53': 213, b'5F': 243, b'42': 206, b'52': 212, b'4B': 248, b'4E': 244, b'62': 196, b'63': 197, b'68': 198, b'69': 199}

esmDict = {b'DB': 236, b'C9': 235, b'D6': 217, b'CA': 233, b'CB': 234, b'CE': 219, b'D1': 237, b'CD': 220, b'D7': 216, b'D3': 239, b'E8': 227, b'D2': 240, b'D9': 225, b'D5': 214, b'DA': 226, b'C6': 200, b'C7': 201, b'C3': 204, b'C2': 203, b'C1': 205, b'C5': 202, b'D4': 215, b'D0': 238}


# Type	dir	msgNameUS	                                msgNameCN	            Notes
# 1000	0	ATTACH  	                                附着	                ATTACH_REQUEST(209)->ATTACH_ACCEPT(206)/ATTACH_REJECT(208)
# 1001	1	ATTACH_ACCEPT  	                            附着接受	            ATTACH_ACCEPT(206)->ATTACH_COMPLETE(207)
# 1002	1	AUTHENTICATION   	                        鉴权	                AUTHENTICATION_REQUEST(212)->AUTHENTICATION_RESPONSE(213)/AUTHENTICATION_FAILURE(210)/AUTHENTICATION_REJECT(211)
# 1003	0	DETACH_UE_ORIGINATING  	                    UE发起脱离	            DETACH_REQUEST(222)(UE ORIGINATING DETACH)->DETACH_ACCEPT(221)(UE ORIGINATING DETACH)
# 1004	1	DETACH_UE_TERMINATED	                    网络发起脱离	        DETACH_REQUEST(222)(UE TERMINATED DETACH)->DETACH_ACCEPT(221)(UE TERMINATED DETACH)
# 1005	1	GUTI_REALLOCATION  	                        GUTI重新指派	        GUTI_REALLOCATION_COMMAND(229)->GUTI_REALLOCATION_COMPLETE(230)
# 1006	1	IDENTIFICATION  	                        认证	                IDENTITY_REQUEST(231)->IDENTITY_RESPONSE(232)
# 1007	1	SECURITY_MODE_CONTROL	                    安全模式控制	        SECURITY_MODE_COMMAND(241)->SECURITY_MODE_COMPLETE(242)/SECURITY_MODE_REJECT(243)
# 1008	0	SERVICE_REQUEST 	                        服务请求	            SERVICE_REQUEST(245)->SERVICE_REJECT(244)
# 1009	0	EXT_SERVICE_REQUEST 	                    扩展服务请求	        EXTENDED_SERVICE_REQUEST(228)->SERVICE_REJECT(244)
# 1010	0	TRACKING_AREA_UPDATING 	                    跟踪区更新	            TRACKING_AREA_UPDATE_REQUEST(249)->TRACKING_AREA_UPDATE_ACCEPT(246)/TRACKING_AREA_UPDATE_REJECT(248)
# 1011	1	TRACKING_AREA_UPDATING_ACCEPT 	            跟踪区更新接受	        TRACKING_AREA_UPDATE_ACCEPT(246)->TRACKING_AREA_UPDATE_COMPLETE(247)
# 1012	1	DEFAULT_EPS_BEARER_CONTEXT_ACTIVATION 	    缺省承载激活	        ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST(205)->ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT(203)/ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT(204)
# 1013	1	DEDICATED_EPS_BEARER_CONTEXT_ACTIVATION	    专用承载激活	        ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST(202)/ACTIVATE_DEDICATED_EPS__BEARER_CONTEXT_ACCEPT(200)/ACTIVATE_DEDICATED_EPS__BEARER_CONTEXT_REJECT(201)
# 1014	0	UE_REQUESTED_BEARER_RESOURCE_ALLOCATION 	UE请求的承载资源分配	BEARER_RESOURCE_ALLOCATION_REQUEST(215)->BEARER_RESOURCE_ALLOCATION_REJECT(214)/ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST(202)/MODIFY_EPS_BEARER_CONTEXT_REQUEST(235)
# 1015	0	UE_REQUESTED_BEARER_RESOURCE_MODIFICATION	UE请求的承载资源变更	BEARER_RESOURCE_MODIFICATION_REQUEST(217)->BEARER_RESOURCE_MODIFICATION_REJECT(216)/ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST(202)/MODIFY_EPS_BEARER_CONTEXT_REQUEST(235)/DEACTIVATE_EPS_CONTEXT_REQUEST(220)
# 1016	1	EPS_BEARER_CONTEXT_DEACTIVATION	            EPS承载上下文去活	    DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST(220)->DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT(219)
# 1017	1	EPS_BEARER_CONTEXT_MODIFICATION 	        EPS承载上下文变更	    MODIFY_EPS_BEARER_CONTEXT_REQUEST(235)->MODIFY_EPS_BEARER_CONTEXT_ACCEPT(233)/MODIFY_EPS_BEARER_CONTEXT_REJECT(234)
# 1018	0	UE_REQUESTED_PDN_CONNECTIVITY 	            UE请求PDN连接	        PDN_CONNECTIVITY_REQUEST(238)->PDN_CONNECTIVITY_REJECT(237)/ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST(205)
# 1019	0	UE_REQUESTED_PDN_DISCONNECT 	            E请求PDN断开	        PDN_DISCONNECT_REQUEST(240)->DEACTIVATE_EPS_CONTEXT_REQUEST(220)/PDN_DISCONNECT_REJECT(239)
# 1020	1	PAGING 	                                    寻呼	                PAGING(287)->SERVICE_REQUEST(245)/EXTENDED_SERVICE_REQUEST(228)

s1apnasPair = {}
s1apnasPair[1000] = {'req': 209,'res':[(206,0),(208,2)]}
s1apnasPair[1001] = {'req': 206,'res':[(207,0)]}
s1apnasPair[1002] = {'req': 212,'res':[(213,0),(210,2),(211,2)]}
s1apnasPair[1003] = {'req': 222,'res':[(221,0)]}                          # use dir to define the proType
# s1apnasPair[1004] = {'req': 222,'res':[(221,0)]}
s1apnasPair[1005] = {'req': 229,'res':[(230,0)]}
s1apnasPair[1006] = {'req': 231,'res':[(232,0)]}
s1apnasPair[1007] = {'req': 241,'res':[(242,0),(243,2)]}
s1apnasPair[1008] = {'req': 245,'res':[(244,2),(1,0)]}                    # 0 means anything that followed except 244
s1apnasPair[1009] = {'req': 228,'res':[(244,2),(1,0)]}
s1apnasPair[1010] = {'req': 249,'res':[(246,0),(248,2)]}
s1apnasPair[1011] = {'req': 246,'res':[(247,0)]}
s1apnasPair[1012] = {'req': 205,'res':[(203,0),(204,2)]}
s1apnasPair[1013] = {'req': 202,'res':[(200,0),(201,2)]}
s1apnasPair[1014] = {'req': 215,'res':[(214,2),(202,0),(235,0)]}
s1apnasPair[1015] = {'req': 217,'res':[(216,2),(202,0),(235,0),(220,0)]}
s1apnasPair[1016] = {'req': 220,'res':[(219,0)]}
s1apnasPair[1017] = {'req': 235,'res':[(233,0),(234,2)]}
s1apnasPair[1018] = {'req': 238,'res':[(237,2),(205,0)]}
s1apnasPair[1019] = {'req': 240,'res':[(220,0),(239,2)]}
s1apnasPair[1020] = {'req': 287,'res':[(245,0),(228,2)]}



# Type	dir	msgNameUS	                msgNameCN	    Notes
# 1100	0	HANDOVER_PREPARATION	    切换准备(切出)	HANDOVER_REQUIRED(273)->HANDOVER_COMMAND(267)/HANDOVER_PREPARATION_FAILURE(270)
# 1101	1	HANDOVER_EXECUTION	        切换执行(切入)	HANDOVER_REQUEST(271)->HANDOVER_REQUEST_ACKNOWLEDGE(272)/HANDOVER_FAILURE(268)
# 1102	0	PATH_SWITCH_REQUEST	        路径切换	    PATH_SWITCH_REQUEST(288)->PATH_SWITCH_REQUEST_ACKNOWLEDGE(289)/PATH_SWITCH_REQUEST_FAILURE(290)
# 1103	0	HANDOVER_CANCELLATION	    切换取消	    HANDOVER_CANCEL(265)->HANDOVER_CANCEL_ACKNOWLEDGE(266)
# 1104	1	E_RAB_SETUP	                ERAB建立	    E_RAB_SETUP_REQUEST(262)->E_RAB SETUP RESPONSE(263)
# 1105	1	E_RAB_MODIFY	            ERAB变更	    E_RAB_MODIFY_REQUEST(257)->E_RAB_MODIFY_RESPONSE(258)
# 1106	1	E_RAB_RELEASE	            ERAB释放	    E_RAB_RELEASE_COMMAND(259)->E_RAB_RELEASE_RESPONSE(261)
# 1107	0	INITIAL_CONTEXT_SETUP	    初始上下文建立	INITIAL_CONTEXT_SETUP_REQUEST(275)->INITIAL_CONTEXT_SETUP_RESPONSE(276)/INITIAL_CONTEXT_SETUP_FAILURE(274)
# 1108	0	RESET	                    重置	        RESET(291)->RESET_ACKNOWLEDGE(292)
# 1109	0	S1_SETUP	                S1建立	        S1_SETUP_REQUEST(395)->S1_SETUP_RESPONSE(396)/S1_SETUP_FAILURE(397)
# 1110	0	UE_CONTEXT_RELEASE	        UE上下文释放	UE_CONTEXT_RELEASE_COMMAND(299)->UE_CONTEXT_RELEASE_COMPLETE(300)
# 1111	1	UE_CONTEXT_MODIFICATION     UE上下文变更	UE_CONTEXT_MODIFICATION_REQUEST(297)->UE_CONTEXT_MODIFICATION_RESPONSE(298)/UE CONTEXT MODIFICATION FAILURE(296)
# 1112	0	ENB_CONFIGURATION_UPDATE	eNodeB配置更新	ENB_CONFIGURATION_UPDATE(253)->ENB_CONFIGURATION_UPDATE_ACKNOWLEDGE(254)/ENB_CONFIGURATION_UPDATE_FAILURE(255)
# 1113	1	MME_CONFIGURATION_UPDATE	MME配置更新	    MME_CONFIGURATION_UPDATE(281)->MME_CONFIGURATION_UPDATE_ACKNOWLEDGE(282)/MME_CONFIGURATION_UPDATE_FAILURE(283)
# 1114	0	WRITE_REPLACE_WARNING	    WRITE_REPLACE_WARNING	WRITE_REPLACE_WARNING_REQUEST->WRITE_REPLACE_WARNING_RESPONSE
# 1115	0	KILL	                    KILL	        KILL_REQUEST->KILL_RESPONSE

s1apnasPair[1100] = {'req': 273,'res':[(267,0),(270,2)]}
s1apnasPair[1101] = {'req': 271,'res':[(272,0),(268,2)]}
s1apnasPair[1102] = {'req': 288,'res':[(289,0),(290,2)]}
s1apnasPair[1103] = {'req': 265,'res':[(266,0)]}
s1apnasPair[1104] = {'req': 262,'res':[(263,0)]}
s1apnasPair[1105] = {'req': 257,'res':[(258,0)]}
s1apnasPair[1106] = {'req': 259,'res':[(261,0)]}
s1apnasPair[1107] = {'req': 275,'res':[(276,0),(274,2)]}
s1apnasPair[1108] = {'req': 291,'res':[(292,0)]}
s1apnasPair[1109] = {'req': 395,'res':[(396,0),(397,2)]}
s1apnasPair[1110] = {'req': 299,'res':[(300,0)]}
s1apnasPair[1111] = {'req': 297,'res':[(298,0),(296,2)]}
s1apnasPair[1112] = {'req': 253,'res':[(254,0),(255,2)]}

temp = {}
s1apnasPair1 = {}
for n in s1apnasPair:
    res = s1apnasPair[n]['res']
    s1apnasPair1[s1apnasPair[n]['req']] = n
    for m in res:
        j = temp.get(m[0],0)
        if j == 0:
            temp1 = [(s1apnasPair[n]['req'],n,m[1])]
            temp[m[0]] = temp1
        else:
            temp[m[0]].append((s1apnasPair[n]['req'],n,m[1]))

s1apnasPair = temp

s1apMMEIP = []

requestMsg = {}
requestMsg[209] = 1000
requestMsg[206] = 1001
requestMsg[212] = 1002
requestMsg[222] = 1003
# requestMsg[222] = 1004
requestMsg[229] = 1005
requestMsg[231] = 1006
requestMsg[241] = 1007
requestMsg[245] = 1008
requestMsg[228] = 1009
requestMsg[249] = 1010
requestMsg[246] = 1011
requestMsg[205] = 1012
requestMsg[202] = 1013
requestMsg[215] = 1014
requestMsg[217] = 1015
requestMsg[220] = 1016
requestMsg[235] = 1017
requestMsg[238] = 1018
requestMsg[240] = 1019
requestMsg[287] = 1020
requestMsg[273] = 1100
requestMsg[271] = 1101
requestMsg[288] = 1102
requestMsg[265] = 1103
requestMsg[262] = 1104
requestMsg[257] = 1105
requestMsg[259] = 1106
requestMsg[275] = 1107
requestMsg[291] = 1108
requestMsg[395] = 1109
requestMsg[299] = 1110
requestMsg[297] = 1111
requestMsg[253] = 1112