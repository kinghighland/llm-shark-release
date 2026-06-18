import sys
import os
import struct
import base64
import datetime
import time
import binascii
import pcap
import status
import diameter
import gtpv2
import re
from socket import inet_ntop, AF_INET6, inet_ntoa 
import sip
import epcDNS
import rtp
import gtp
from collections import Counter

def decodeLLC(xdr,raw):
    if len(raw) < 5:
        print(xdr['display'],' LLC too small, the length is',len(raw))
        return
    address = struct.unpack('!B',raw[0:1])[0]
    control = struct.unpack('!B',raw[1:2])[0]
    pos = 0
    if (control >> 7) == 0:
        pos = 3
        control = struct.unpack('!B',raw[3:4])[0] & 3
        lengthSACK = 0
        if control == 3:
            lengthSACK = struct.unpack('!B',raw[4:5])[0] & 31
            lengthSACK = (lengthSACK + 7) // 8
        pos = 4 + lengthSACK
    elif (control >> 6) == 2:
        pos = 2
        control = struct.unpack('!B',raw[2:3])[0] & 3
        lengthSACK = 0
        if control == 3:
            lengthSACK = struct.unpack('!B',raw[3:4])[0] & 31
            lengthSACK = (lengthSACK + 7) // 8
        pos = 3 + lengthSACK
    elif (control >> 5) == 6:
        pos = 2
    elif (control >> 5) == 3:
        pos = 1
    pos += 1
    if address&15 == 0:
        print(xdr['display'],' Reserved')
    elif address&15 == 1:
        # print(xdr['display'],' LLGMM')
        if (len(raw) - 3 - pos) > 0:
            msgType = struct.unpack('!B',raw[pos+1:pos+2])[0]
            xdr['msgType'] = gbNASPair.get(msgType,0)
            if xdr['msgType'] == 0:
                print(xdr['display'],' Error msgType',msgType)
            else:
                if xdr['msgType'] == 112:
                    print(xdr['display'],' ATTACH_REQUEST')
                elif xdr['msgType'] == 113:
                    print(xdr['display'],' ATTACH_ACCEPT')
                elif xdr['msgType'] == 114:
                    print(xdr['display'],' ATTACH_COMPLETE')
                elif xdr['msgType'] == 115:
                    print(xdr['display'],' ATTACH_REJECT')
                elif xdr['msgType'] == 116:
                    print(xdr['display'],' AUTH_AND_CIPHERING_REQUEST')
                elif xdr['msgType'] == 117:
                    print(xdr['display'],' AUTH_AND_CIPHERING_RESPONSE')
                elif xdr['msgType'] == 118:
                    print(xdr['display'],' AUTH_AND_CIPHERING_REJECT')
                elif xdr['msgType'] == 119:
                    print(xdr['display'],' AUTH_AND_CIPHERING_FAILURE')
                elif xdr['msgType'] == 120:
                    if xdr['dir'] == '0':
                        print(xdr['display'],' DETACH_REQUEST(UE)')
                    else:
                        print(xdr['display'],' DETACH_REQUEST(Network)')
                        xdr['msgType'] = 176
                elif xdr['msgType'] == 121:
                    print(xdr['display'],' DETACH_ACCEPT')
                elif xdr['msgType'] == 122:
                    print(xdr['display'],' IDENTITY_REQUEST')
                elif xdr['msgType'] == 123:
                    print(xdr['display'],' IDENTITY_RESPONSE')
                elif xdr['msgType'] == 124:
                    print(xdr['display'],' RAU_REQUEST')
                elif xdr['msgType'] == 125:
                    print(xdr['display'],' RAU_ACCEPT')
                elif xdr['msgType'] == 126:
                    print(xdr['display'],' RAU_COMPLETE')
                elif xdr['msgType'] == 127:
                    print(xdr['display'],' RAU_REJECT')
                elif xdr['msgType'] == 128:
                    print(xdr['display'],' SERVICE_REQUEST')
                elif xdr['msgType'] == 129:
                    print(xdr['display'],' SERVICE_ACCEPT')
                elif xdr['msgType'] == 130:
                    print(xdr['display'],' SERVICE_REJECT')
                elif xdr['msgType'] == 158:
                    print(xdr['display'],' ACTIVATE_2nd_PDP_CONTEXT_REQUEST')
                elif xdr['msgType'] == 159:
                    print(xdr['display'],' ACTIVATE_2nd_PDP_CONTEXT_ACCEPT')
                elif xdr['msgType'] == 160:
                    print(xdr['display'],' ACTIVATE_2nd_PDP_CONTEXT_REJECT')
                elif xdr['msgType'] == 161:
                    print(xdr['display'],' ACTIVATE_PDP_CONTEXT_REQUEST')
                elif xdr['msgType'] == 162:
                    print(xdr['display'],' ACTIVATE_PDP_CONTEXT_ACCEPT')
                elif xdr['msgType'] == 163:
                    print(xdr['display'],' ACTIVATE_PDP_CONTEXT_REJECT')
                elif xdr['msgType'] == 164:
                    if xdr['dir'] == '0':
                        print(xdr['display'],' DEACTIVATE_PDP_CONTEXT_REQUEST(UE)')
                    else:
                        xdr['msgType'] = 177
                        print(xdr['display'],' DEACTIVATE_PDP_CONTEXT_REQUEST(Network)')
                elif xdr['msgType'] == 165:
                    print(xdr['display'],' DEACTIVATE_PDP_CONTEXT_ACCEPT')
                elif xdr['msgType'] == 166:
                    print(xdr['display'],' MODIFY_PDP_CONTEXT_REQUEST(UL)')
                elif xdr['msgType'] == 167:
                    print(xdr['display'],' MODIFY_PDP_CONTEXT_REQUEST(DL)')
                elif xdr['msgType'] == 168:
                    print(xdr['display'],' MODIFY_PDP_CONTEXT_ACCEPT(UL)')
                elif xdr['msgType'] == 169:
                    print(xdr['display'],' MODIFY_PDP_CONTEXT_ACCEPT(DL)')
                elif xdr['msgType'] == 170:
                    print(xdr['display'],' MODIFY_PDP_CONTEXT_REJECT')
                elif xdr['msgType'] == 171:
                    print(xdr['display'],' REQUEST_PDP_CONTEXT_ACTIVATION')
                elif xdr['msgType'] == 172:
                    print(xdr['display'],' REQUEST_PDP_CONTEXT_ACTIVATION_REJECT')
                cacheNASXDR(xdr)
    elif address&15 == 2:
        print(xdr['display'],' TOM2')
    elif address&15 == 3:
        print(xdr['display'],' LL3')
    elif address&15 == 4:
        print(xdr['display'],' Reserved')
    elif address&15 == 5:
        print(xdr['display'],' LL5')
    elif address&15 == 6:
        print(xdr['display'],' Reserved')
    elif address&15 == 7:
        print(xdr['display'],' LLSMS')
    elif address&15 == 8:
        print(xdr['display'],' TOM8')
    elif address&15 == 9:
        print(xdr['display'],' LL9')
    elif address&15 == 10:
        print(xdr['display'],' Reserved')
    elif address&15 == 11:
        print(xdr['display'],' LL11')
    elif address&15 == 12:
        print(xdr['display'],' Reserved')
    elif address&15 == 13:
        print(xdr['display'],' Reserved')
    elif address&15 == 14:
        print(xdr['display'],' Reserved')
    elif address&15 == 15:
        print(xdr['display'],' Reserved')
    return

def decodeGb(xdr,raw,flush):
    xdr['display'] += ', Gb'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','2'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,0,''
    
    pduType = struct.unpack('!B',raw[0:1])[0]
    pduType1 = 0
    if pduType == 0:
        # print(xdr['display'],' NS-UNITDATA')
        controlBits,bvci = struct.unpack('!BH',raw[1:4])
        if (controlBits >> 2) != 0:
            print('Error Control Bits is not zero.')
        else:
            pduType1 = struct.unpack('!B',raw[4:5])[0]
            if pduType1 == 0:
                #print(xdr['display'],' NS-UNITDATA, BSSGP DL-UNITDATA')
                xdr['dir'] = '1'
                # if xdr['sip'][0] not in gbSGSNIP: gbSGSNIP.append(xdr['sip'][0])
                # if xdr['dip'][0] not in gbBSCIP: gbBSCIP.append(xdr['dip'][0])
                tlli = struct.unpack('!I',raw[5:9])[0]
                xdr['tlli'] = tlli
                pos = 12
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 13:
                        nextByte = struct.unpack('!B',raw[pos:pos+1])[0]
                        odd = (nextByte >> 3) & 1
                        msidType = nextByte & 7
                        if msidType == 1:
                            string = '{:X}'.format(nextByte>>4) + "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+length1]]) + 'F'
                            xdr['imsi'] = string[:-odd]
                            tlliIMSI[tlli] = xdr['imsi']
                        pos += length1
                    elif eleID == 8:
                        xdr['cgi'] = struct.unpack('!H',raw[pos+3:pos+5])[0]*100000
                        xdr['cgi'] += struct.unpack('!H',raw[pos+6:pos+8])[0]
                        pos += length1
                    elif eleID == 31:
                        tlliOld = struct.unpack('!I',raw[pos+3:pos+7])[0]
                        imsi = tlliIMSI.get(tlliOld,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            tlliIMSI[tlli] = xdr['imsi']
                        pos += length1
                    elif eleID == 14:
                        raw1 = struct.unpack('!'+str(length1)+'s',raw[pos:pos+length1])[0]
                        decodeLLC(xdr,raw1)
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 1:
                # print(xdr['display'],' NS-UNITDATA, BSSGP UL-UNITDATA')
                xdr['dir'] = '0'
                tlli = struct.unpack('!I',raw[5:9])[0]
                xdr['tlli'] = tlli
                pos = 12
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 13:
                        nextByte = struct.unpack('!B',raw[pos:pos+1])[0]
                        odd = (nextByte >> 3) & 1
                        msidType = nextByte & 7
                        if msidType == 1:
                            string = '{:X}'.format(nextByte>>4) + "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+length1]]) + 'F'
                            xdr['imsi'] = string[:-odd]
                            tlliIMSI[tlli] = xdr['imsi']
                        pos += length1
                    elif eleID == 8:
                        xdr['cgi'] = struct.unpack('!H',raw[pos+3:pos+5])[0]*100000
                        xdr['cgi'] += struct.unpack('!H',raw[pos+6:pos+8])[0]
                        pos += length1
                    elif eleID == 14:
                        raw1 = struct.unpack('!'+str(length1)+'s',raw[pos:pos+length1])[0]
                        decodeLLC(xdr,raw1)
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 2:
                print(xdr['display'],' NS-UNITDATA, BSSGP RA-CAPABILITY')
                xdr['dir'] = '1'
            elif pduType1 == 3:
                print(xdr['display'],' NS-UNITDATA, BSSGP PTM-UNITDATA')
                xdr['dir'] = '1'
            elif pduType1 == 6:
                print(xdr['display'],' NS-UNITDATA, BSSGP PAGING PS')
                xdr['dir'] = '1'
                xdr['msgType'] = 104
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 13:
                        nextByte = struct.unpack('!B',raw[pos:pos+1])[0]
                        odd = (nextByte >> 3) & 1
                        msidType = nextByte & 7
                        if msidType == 1:
                            string = '{:X}'.format(nextByte>>4) + "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+length1]]) + 'F'
                            xdr['imsi'] = string[:-odd]
                    elif eleID == 32:                          # TMSI/P-TMSI
                        xdr['tmsi'] = struct.unpack('!I',raw[pos:pos+4])[0]
                    pos += length1
                if xdr.get('tmsi',0) != 0:
                    tmsiIMSI[xdr['tmsi']] = xdr['imsi']
            elif pduType1 == 7:
                print(xdr['display'],' NS-UNITDATA, BSSGP PAGING CS')
                xdr['dir'] = '1'
            elif pduType1 == 8:
                print(xdr['display'],' NS-UNITDATA, BSSGP RA-CAPABILITY-UPDATE')
                xdr['dir'] = '0'
            elif pduType1 == 9:
                print(xdr['display'],' NS-UNITDATA, BSSGP RA-CAPABILITY-UPDATE-ACK')
                xdr['dir'] = '1'
            elif pduType1 == 10:
                print(xdr['display'],' NS-UNITDATA, BSSGP RADIO-STATUS')
                xdr['dir'] = '0'
                xdr['msgType'] = 105
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 13:                           # imsi
                        nextByte = struct.unpack('!B',raw[pos:pos+1])[0]
                        odd = (nextByte >> 3) & 1
                        msidType = nextByte & 7
                        if msidType == 1:
                            string = '{:X}'.format(nextByte>>4) + "".join(['{:02X}'.format(((x&15)<<4)+(x>>4)) for x in raw[pos+1:pos+length1]]) + 'F'
                            xdr['imsi'] = string[:-odd]
                        pos += length1
                    elif eleID == 31:                          # old tlli
                        tlli = struct.unpack('!I',raw[pos:pos+4])[0]
                        imsi = tlliIMSI.get(tlli,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            xdr['tlli'] = tlli
                        pos += length1
                    elif eleID == 32:                          # TMSI/P-TMSI
                        tmsi = struct.unpack('!I',raw[pos:pos+4])[0]*100000
                        imsi = tmsiIMSI.get(tmsi,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 11:
                print(xdr['display'],' NS-UNITDATA, BSSGP SUSPEND')
                xdr['dir'] = '0'
                xdr['msgType'] = 109
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 31:                          # old tlli
                        tlli = struct.unpack('!I',raw[pos:pos+4])[0]
                        imsi = tlliIMSI.get(tlli,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            xdr['tlli'] = tlli
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 12:
                print(xdr['display'],' NS-UNITDATA, BSSGP SUSPEND-ACK')
                xdr['dir'] = '1'
                xdr['msgType'] = 110
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 31:                          # old tlli
                        tlli = struct.unpack('!I',raw[pos:pos+4])[0]
                        imsi = tlliIMSI.get(tlli,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            xdr['tlli'] = tlli
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 13:
                print(xdr['display'],' NS-UNITDATA, BSSGP SUSPEND-NACK')
                xdr['dir'] = '1'
                xdr['msgType'] = 111
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 7:
                        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
                        pos += length1
                    elif eleID == 31:                          # old tlli
                        tlli = struct.unpack('!I',raw[pos:pos+4])[0]
                        imsi = tlliIMSI.get(tlli,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            xdr['tlli'] = tlli
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 14:
                print(xdr['display'],' NS-UNITDATA, BSSGP RESUME')
                xdr['dir'] = '0'
                xdr['msgType'] = 106
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 31:                          # old tlli
                        tlli = struct.unpack('!I',raw[pos:pos+4])[0]
                        imsi = tlliIMSI.get(tlli,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            xdr['tlli'] = tlli
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 15:
                print(xdr['display'],' NS-UNITDATA, BSSGP RESUME-ACK')
                xdr['dir'] = '1'
                xdr['msgType'] = 107
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 31:                          # old tlli
                        tlli = struct.unpack('!I',raw[pos:pos+4])[0]
                        imsi = tlliIMSI.get(tlli,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            xdr['tlli'] = tlli
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 16:
                print(xdr['display'],' NS-UNITDATA, BSSGP RESUME-NACK')
                xdr['dir'] = '1'
                xdr['msgType'] = 108
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 7:
                        xdr['Cause'] = struct.unpack('!B',raw[pos:pos+1])[0]
                        pos += length1
                    elif eleID == 31:                          # old tlli
                        tlli = struct.unpack('!I',raw[pos:pos+4])[0]
                        imsi = tlliIMSI.get(tlli,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            xdr['tlli'] = tlli
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 32:
                print(xdr['display'],' NS-UNITDATA, BSSGP BVC-BLOCK')
                xdr['dir'] = '0'
            elif pduType1 == 33:
                print(xdr['display'],' NS-UNITDATA, BSSGP BVC-BLOCK-ACK')
                xdr['dir'] = '1'
            elif pduType1 == 34:
                print(xdr['display'],' NS-UNITDATA, BSSGP BVC-RESET')
                xdr['dir'] = '0'
                # if xdr['sip'][0] in gbSGSNIP: xdr['dir'] = '1'
                # if xdr['dip'][0] in gbSGSNIP: xdr['dir'] = '0'
                # if xdr['sip'][0] in gbBSCIP: xdr['dir'] = '0'
                # if xdr['dip'][0] in gbBSCIP: xdr['dir'] = '1'
            elif pduType1 == 35:
                print(xdr['display'],' NS-UNITDATA, BSSGP BVC-RESET-ACK')
                xdr['dir'] = '1'
                # if xdr['sip'][0] in gbSGSNIP: xdr['dir'] = '1'
                # if xdr['dip'][0] in gbSGSNIP: xdr['dir'] = '0'
                # if xdr['sip'][0] in gbBSCIP: xdr['dir'] = '0'
                # if xdr['dip'][0] in gbBSCIP: xdr['dir'] = '1'
            elif pduType1 == 36:
                print(xdr['display'],' NS-UNITDATA, BSSGP BVC-UNBLOCK')
                xdr['dir'] = '0'
            elif pduType1 == 37:
                print(xdr['display'],' NS-UNITDATA, BSSGP BVC-UNBLOCK-ACK')
                xdr['dir'] = '1'
            elif pduType1 == 38:
                print(xdr['display'],' NS-UNITDATA, BSSGP FLOW-CONTROL-BVC')
                xdr['dir'] = '0'
            elif pduType1 == 39:
                print(xdr['display'],' NS-UNITDATA, BSSGP FLOW-CONTROL-BVC-ACK')
                xdr['dir'] = '1'
            elif pduType1 == 40:
                print(xdr['display'],' NS-UNITDATA, BSSGP FLOW-CONTROL-MS')
                xdr['dir'] = '0'
            elif pduType1 == 41:
                print(xdr['display'],' NS-UNITDATA, BSSGP FLOW-CONTROL-MS-ACK')
                xdr['dir'] = '1'
            elif pduType1 == 42:
                print(xdr['display'],' NS-UNITDATA, BSSGP FLUSH-LL')
                xdr['dir'] = '1'
                xdr['msgType'] = 101
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 31:                          # old tlli
                        tlli = struct.unpack('!I',raw[pos:pos+4])[0]
                        imsi = tlliIMSI.get(tlli,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            xdr['tlli'] = tlli
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 43:
                print(xdr['display'],' NS-UNITDATA, BSSGP FLUSH-LL-ACK')
                xdr['dir'] = '0'
                xdr['msgType'] = 102
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 31:                          # old tlli
                        tlli = struct.unpack('!I',raw[pos:pos+4])[0]
                        imsi = tlliIMSI.get(tlli,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            xdr['tlli'] = tlli
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 44:
                print(xdr['display'],' NS-UNITDATA, BSSGP LLC-DISCARDED')
                xdr['dir'] = '0'
                xdr['msgType'] = 103
                pos = 5
                length = len(raw)
                while pos < length:
                    eleID,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
                    length1 = struct.unpack('!B',raw[pos:pos+1])[0]
                    if (length1 >>7) == 1:
                        length1,pos = struct.unpack('!B',raw[pos:pos+1])[0] & 127, pos + 1
                    else:
                        length1,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
                    if length1 > length-pos:
                        print(xdr['display'],' Malformed packet')
                        return
                    if eleID == 31:                          # old tlli
                        tlli = struct.unpack('!I',raw[pos:pos+4])[0]
                        imsi = tlliIMSI.get(tlli,'0')
                        if imsi != '0':
                            xdr['imsi'] = imsi
                            xdr['tlli'] = tlli
                        pos += length1
                    else:
                        pos += length1
            elif pduType1 == 64:
                print(xdr['display'],' NS-UNITDATA, BSSGP SGSN-INVOKE-TRACE')
                xdr['dir'] = '1'
            elif pduType1 == 65:
                print(xdr['display'],' NS-UNITDATA, BSSGP STATUS')
                xdr['dir'] = '0'
                # if xdr['sip'][0] in gbSGSNIP: xdr['dir'] = '1'
                # if xdr['dip'][0] in gbSGSNIP: xdr['dir'] = '0'
                # if xdr['sip'][0] in gbBSCIP: xdr['dir'] = '0'
                # if xdr['dip'][0] in gbBSCIP: xdr['dir'] = '1'
            else:
                print('Error BSSGP UDP Type', pduType)
            if pduType1 in (6,10,11,12,13,14,15,16,42,43,44):
                cacheGBXDR(xdr)
    elif pduType == 2:
        print(xdr['display'],' NS-RESET')
    elif pduType == 3:
        print(xdr['display'],' NS-RESET-ACK')
    elif pduType == 4:
        print(xdr['display'],' NS-BLOCK')
    elif pduType == 5:
        print(xdr['display'],' NS-BLOCK-ACK')
    elif pduType == 6:
        print(xdr['display'],' NS-UNBLOCK')
    elif pduType == 7:
        print(xdr['display'],' NS-UNBLOCK-ACK')
    elif pduType == 8:
        print(xdr['display'],' NS-STATUS')
    elif pduType == 10:
        print(xdr['display'],' NS-ALIVE')
    elif pduType == 11:
        print(xdr['display'],' NS-ALIVE-ACK')
    else:
        print('Error NS UDP Type', pduType)

    return

def outputGBXDR(xdr):
    global gbOutputFile
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'Gb'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','','',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if gbOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        gbOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_Gb_Msg_'+b+'.tmp')
        gbOutputFile = open(gbOutputFileName,'w')
        if gbOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(gbOutputFile)
    gbOutputFile.writelines(string)
    return

def cacheGBXDR(xdr):
    global gbXDR,gbXDR1,lastUpdateTimeGB
    if xdr['imsi'] != '0':
        outputGBXDR(xdr)
    else:
        gbXDR.append(xdr)
    if xdr['ts'][0] - lastUpdateTimeGB > 10:
        outputXDR = []
        lastUpdateTimeGB = xdr['ts'][0]
        for tempxdr in gbXDR:
            if tempxdr.get('tlli',0) != 0:
                tempxdr['imsi'] = tlliIMSI.get(tempxdr['tlli'],'0')
            if tempxdr['imsi'] == '0':
                gbXDR1.append(tempxdr)
            else:
                outputXDR.append(tempxdr)
        for xdr in outputXDR:
            outputGBXDR(xdr)
        gbXDR.clear()
    return

def flushGBXDR():
    for tempxdr in gbXDR:
        if tempxdr.get('tlli',0) != 0:
            tempxdr['imsi'] = tlliIMSI.get(tempxdr['tlli'],'0')
        outputGBXDR(tempxdr)
    gbXDR.clear()
    for tempxdr in gbXDR1:
        if tempxdr.get('tlli',0) != 0:
            tempxdr['imsi'] = tlliIMSI.get(tempxdr['tlli'],'0')
        outputGBXDR(tempxdr)
    gbXDR1.clear()
    return

def outputNASXDR(xdr):
    global nasOutputFile
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
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','','',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if nasOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        nasOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_NAS_Msg_'+b+'.tmp')
        nasOutputFile = open(nasOutputFileName,'w')
        if nasOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(nasOutputFile)
    nasOutputFile.writelines(string)
    return

def cacheNASXDR(xdr):
    global nasXDR,nasXDR1,lastUpdateTimeNAS
    if xdr['imsi'] != '0':
        outputNASXDR(xdr)
    else:
        nasXDR.append(xdr)
    if xdr['ts'][0] - lastUpdateTimeNAS > 10:
        outputXDR = []
        lastUpdateTimeNAS = xdr['ts'][0]
        for tempxdr in nasXDR:
            if tempxdr.get('tlli',0) != 0:
                tempxdr['imsi'] = tlliIMSI.get(tempxdr['tlli'],'0')
            if tempxdr['imsi'] == '0':
                nasXDR1.append(tempxdr)
            else:
                outputXDR.append(tempxdr)
        for xdr in outputXDR:
            outputNASXDR(xdr)
        nasXDR.clear()

    return

def flushNASXDR():

    for tempxdr in nasXDR:
        if tempxdr.get('tlli',0) != 0:
            tempxdr['imsi'] = tlliIMSI.get(tempxdr['tlli'],'0')
        outputNASXDR(tempxdr)
    nasXDR.clear()
    for tempxdr in nasXDR1:
        if tempxdr.get('tlli',0) != 0:
            tempxdr['imsi'] = tlliIMSI.get(tempxdr['tlli'],'0')
        outputNASXDR(tempxdr)
    nasXDR1.clear()
    return

lastUpdateTimeNAS = 0
lastUpdateTimeGB = 0
gbOutputFile = None
nasOutputFile = None

gbXDR = []
gbXDR1 = []

nasXDR = []
nasXDR1 = []

tlliIMSI = {}
tmsiIMSI = {}

# gbSGSNIP = []
# gbBSCIP = []

gbNASPair = {}
gbNASPair[1] = 112     # ATTACH_REQUEST
gbNASPair[2] = 113     # ATTACH_ACCEPT
gbNASPair[3] = 114     # ATTACH_COMPLETE
gbNASPair[4] = 115     # ATTACH_REJECT
gbNASPair[6] = 121     # DETACH_ACCEPT
gbNASPair[5] = 120     # DETACH_REQUEST(UE)
gbNASPair[8] = 124     # RAU_REQUEST
gbNASPair[9] = 125     # RAU_ACCEPT
gbNASPair[10] = 126    # RAU_COMPLETE
gbNASPair[11] = 127    # RAU_REJECT
gbNASPair[12] = 128    # SERVICE_REQUEST
gbNASPair[13] = 129    # SERVICE_ACCEPT
gbNASPair[14] = 130    # SERVICE_REJECT
gbNASPair[18] = 116    # AUTH_AND_CIPHERING_REQUEST
gbNASPair[19] = 117    # AUTH_AND_CIPHERING_RESPONSE
gbNASPair[20] = 118    # AUTH_AND_CIPHERING_REJECT
gbNASPair[28] = 119    # AUTH_AND_CIPHERING_FAILURE
gbNASPair[21] = 122    # IDENTITY_REQUEST
gbNASPair[22] = 123    # IDENTITY_RESPONSE
gbNASPair[65] = 161    # ACTIVATE_PDP_CONTEXT_REQUEST
gbNASPair[66] = 162    # ACTIVATE_PDP_CONTEXT_ACCEPT
gbNASPair[67] = 163    # ACTIVATE_PDP_CONTEXT_REJECT
gbNASPair[68] = 171    # REQUEST_PDP_CONTEXT_ACTIVATION
gbNASPair[69] = 172    # REQUEST_PDP_CONTEXT_ACTIVATION_REJECT
gbNASPair[70] = 164    # DEACTIVATE_PDP_CONTEXT_REQUEST(UE)
gbNASPair[71] = 165    # DEACTIVATE_PDP_CONTEXT_ACCEPT
gbNASPair[72] = 167    # MODIFY_PDP_CONTEXT_REQUEST(DL)
gbNASPair[73] = 169    # MODIFY_PDP_CONTEXT_ACCEPT(DL)
gbNASPair[74] = 166    # MODIFY_PDP_CONTEXT_REQUEST(UL)
gbNASPair[75] = 168    # MODIFY_PDP_CONTEXT_ACCEPT(UL)
gbNASPair[76] = 170    # MODIFY_PDP_CONTEXT_REJECT
gbNASPair[77] = 158    # ACTIVATE_2nd_PDP_CONTEXT_REQUEST
gbNASPair[78] = 159    # ACTIVATE_2nd_PDP_CONTEXT_ACCEPT
gbNASPair[79] = 160    # ACTIVATE_2nd_PDP_CONTEXT_REJECT