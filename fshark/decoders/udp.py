import sys
import os
import struct
import base64
import datetime
import binascii
import pcap
import status
import diameter
import gtpv2
import re
import sip
import epcDNS
import rtp
import gtp
import gb
import a11
import pfcp
import ethernet
from collections import Counter
from string import printable

p = [x for x in printable.encode()]

def buildUDPDecode(xdr,raw):
    # check for very short byte
    if len(raw) == 1:
        pass
    else:
        # check CDMA A11
        found = True
        i = 0
        rawLength = len(raw)
        if(rawLength <= 8):
            socket1Count = ipPortProtocol.get((xdr['sip'][len(xdr['sip'])-1],xdr['sport']),(0,'Not found port in udpPortProtocol'))
            socket2Count = ipPortProtocol.get((xdr['dip'][len(xdr['dip'])-1],xdr['dport']),(0,'Not found port in udpPortProtocol'))
            socket1Count_0 = socket1Count[0] + 1
            socket2Count_0 = socket2Count[0] + 1    
            ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (socket1Count_0,'Unkown port counted '+str(socket1Count_0))
            ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (socket2Count_0,'Unkown port counted '+str(socket2Count_0))
            return (socket1Count_0,'Unkown port counted '+str(socket1Count_0))
        nextByte = struct.unpack('!B',raw[i:i+1])[0]
        if nextByte == 1:       # A11_REGISTRATION_REQUEST
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
            i += 1
            nextByte = struct.unpack('!B',raw[i:i+1])[0]   # Code = [00H, 80H, 81H, 82H, 83H, 85H, 86H, 88H, 89H, 8AH, 8DH]
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
            i += 1
            nextByte = struct.unpack('!H',raw[i:i+2])[0]   # Reserved = [00 00H]
            if nextByte != 0:
                found = False
            else:
                i += 2
                nextByte = struct.unpack('!B',raw[i:i+1])[0]  # Status = [00H, 80H, 83H, 85H, 86H]
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
            i += 1
            nextByte = struct.unpack('!H',raw[i:i+2])[0]   # Reserved = [00 00H]
            if nextByte != 0:
                found = False
            else:
                i += 2
                nextByte = struct.unpack('!B',raw[i:i+1])[0]  # Status = [00H, 80H, 83H, 85H, 86H, C9H]
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
                if nextByte in (32,39,134):
                    i += struct.unpack('!B',raw[i:i+1])[0]+1
                else:
                    i += 1
                    i += struct.unpack('!H',raw[i:i+2])[0]+2
        if found == True:
            ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (a11.decodeA11,'Found port RTP')
            ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (a11.decodeA11,'Found port RTP')
            return(a11.decodeA11,'Found port CDMA A11')

        # check GTPv2
        found = True
        i = 0
        rawLength = len(raw)
        nextByte = struct.unpack('!B',raw[i:i+1])[0]
        i += 1
        if (nextByte>>5) == 2 and rawLength > 8:
            msgType,msgLength = struct.unpack('!BH',raw[i:i+3])
            i += 3
            if 40 <= msgType <=63:
                found = False
            elif 74 <= msgType <= 94:
                found = False
            elif 103 <= msgType <= 127:
                found = False
            elif 142 <= msgType <= 148:
                found = False
            elif 181 <= msgType <= 199:
                found = False
            elif 202 <= msgType <= 210:
                found = False
            elif 213 <= msgType <= 230:
                found = False
            elif 237 <= msgType <= 255:
                found = False
            else:
                i += 4 + ((nextByte >> 3) & 1) * 4
                while i < rawLength-4:
                    ieType,ieLength,cr = struct.unpack('!BHB',raw[i:i+4])
                    i += ieLength + 4
                    if ieType == 0:
                        break
                    if ieType > 168:
                        found = False
                    if i > rawLength:
                        found = False
                if found == True:
                    if msgType in (1,32,36,34):
                        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (gtp.decodeGTP,'Found port GTPv2')
                    elif msgType in (2,33,37,35):
                        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (gtp.decodeGTP,'Found port GTPv2')
                    return (gtp.decodeGTP,'Found port GTPv2')

        # check SIP
        try:
            try:
                string1 = raw.decode()
            except:
                raw1 = bytearray(raw)
                length_raw = len(raw1)
                for n in range(length_raw):
                    if raw1[n] not in p:
                        raw1[n] = 95             # convert a non printable charactor to a "_".
                string1 = raw1.decode()
            m = regexSIPRequest.match(string1)
            if m != None:
                ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (sip.decodeUDPSIP,'Found port SIP')
                return (sip.decodeUDPSIP,'Found port SIP')
            else:
                m = regexSIPStatus.match(string1)
                if m != None:
                    ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (sip.decodeUDPSIP,'Found port SIP')
                    return (sip.decodeUDPSIP,'Found port SIP')
        except Exception as err:
            pass

        # check AMR
        nextBytes = struct.unpack('!H',raw[:2])[0]
        if nextBytes == 32864 and 12 <= len(raw) <= 40:
            ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (rtp.decodeRTP,'Found port RTP')
            ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (rtp.decodeRTP,'Found port RTP')
            ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport']+1)] = (rtp.decodeRTCP,'Found port RTCP')
            ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport']+1)] = (rtp.decodeRTCP,'Found port RTCP')
            return(rtp.decodeRTP,'Found port RTP')

        # check VXLAN
        if nextBytes == 2048 and xdr['dport'] == 4789 and len(raw) > 42:
            return (9999, 'Found ethernet')
        
        # check GTP-C
        if xdr['sport'] == 2123 or xdr['dport'] == 2123:
            return(gtp.decodeGTP,'Found port GTP-C')
        
        # check Gb
        if xdr['sport'] == 30924 or xdr['dport'] == 30924:
            return(gb.decodeGb,'Found port Gb')
        
        # check PCFP
        if (len(raw)>=8):
            Flags, msgType, msgLength = struct.unpack("!BBH",raw[0:4])
            if(msgLength == (len(raw) - 4)):
                if((msgType > 0 and msgType <=15) or (msgType >= 50 and msgType <= 57)):
                    if(((Flags>>5) == 1) and (Flags & 0x18) == 0):
                        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (pfcp.decodePFCP,'Found port PFCP')
                        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (pfcp.decodePFCP,'Found port PFCP')
                        return(pfcp.decodePFCP,'Found port PFCP')
        # Others

    if xdr['sport'] in wellKnownPort:
        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (999,'Well known port'+str(xdr['sport']))
        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (999,'Well known port'+str(xdr['sport']))
        return (999,'Well known port'+str(xdr['sport']))
    if xdr['dport'] in wellKnownPort:
        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (999,'Well known port'+str(xdr['dport']))
        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (999,'Well known port'+str(xdr['dport']))
        return (999,'Well known port'+str(xdr['dport']))
    socket1Count = ipPortProtocol.get((xdr['sip'][len(xdr['sip'])-1],xdr['sport']),(0,'Not found port in udpPortProtocol'))
    socket2Count = ipPortProtocol.get((xdr['dip'][len(xdr['dip'])-1],xdr['dport']),(0,'Not found port in udpPortProtocol'))
    socket1Count_0 = socket1Count[0] + 1
    socket2Count_0 = socket2Count[0] + 1    
    ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (socket1Count_0,'Unkown port counted '+str(socket1Count_0))
    ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (socket2Count_0,'Unkown port counted '+str(socket2Count_0))
    return (socket1Count_0,'Unkown port counted '+str(socket1Count_0))

def decodeUDP(xdr,raw):
    '''found = status.udp_dup_list_1.get((raw,'_'.join(str(xdr['sip'])),'_'.join(str(xdr['dip']))),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup UDP Packet')
            return
        else:
            xdr['dup'] = True
    found = status.udp_dup_list_2.get((raw,'_'.join(str(xdr['sip'])),'_'.join(str(xdr['dip']))),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup UDP Packet')
            return
        else:
            xdr['dup'] = True
    found = status.udp_dup_list_3.get((raw,'_'.join(str(xdr['sip'])),'_'.join(str(xdr['dip']))),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup UDP Packet')
            return
        else:
            xdr['dup'] = True
    status.udp_dup_list_3 = status.udp_dup_list_2
    status.udp_dup_list_2 = status.udp_dup_list_1
    status.udp_dup_list_1 = {}
    status.udp_dup_list_1[(raw,'_'.join(str(xdr['sip'])),'_'.join(str(xdr['dip'])))] = xdr['ts']'''


    xdr['display'] += ', UDP'
    xdr['Level'] += 1

    if(len(raw) <= 8):
        return
    sport,dport,length,checksum = struct.unpack('!4H',raw[:8])
    
    
    xdr['sport'] = sport
    xdr['dport'] = dport
    # GmOverGTP有两层ip和port，实现ip+port配置网元的需求需要外层的port，但目前的port会被内层覆盖掉。为了避免过大改动，所以新增一个字段，只用来输出外层port
    if xdr.get('sport1', '') == '': xdr['sport1'] = sport
    if xdr.get('dport1', '') == '': xdr['dport1'] = dport
    
    if sport == dport and sport >= 30000:
        gb.decodeGb(xdr,raw[8:],False)
        return

    if length == 8:
        del xdr
        return

    if sport == 53 or dport == 53:
        epcDNS.decodeEPCDNS(xdr,raw[8:length],False)
        return
    elif sport == 2152 or dport == 2152:
        gtp.decodeGTP(xdr,raw[8:length],False)
        return

    decodeFunction1 = ipPortProtocol.get((xdr['sip'][len(xdr['sip'])-1],xdr['sport']),(0,'Not found port in udpPortProtocol'))
    if decodeFunction1[0] not in [x for x in range(0,102)]+[999]:
        decodeFunction1[0](xdr,raw[8:length],False)
    else:
        decodeFunction2 = ipPortProtocol.get((xdr['dip'][len(xdr['dip'])-1],xdr['dport']),(0,'Not found port in sctpPortProtocol'))
        if decodeFunction2[0] not in [x for x in range(0,102)]+[999]:
            decodeFunction2[0](xdr,raw[8:length],False)
        else:
            if decodeFunction1[0] >100:
                print(xdr['display'],decodeFunction1[1])
                del xdr
                return
            elif decodeFunction2[0] > 100:
                print(xdr['display'],decodeFunction2[1])
                del xdr
                return
            else:
                decodeFunction = buildUDPDecode(xdr,raw[8:length])
                if decodeFunction[0] == 999:
                    print(xdr['display'],decodeFunction[1])
                    del xdr
                    return
                elif decodeFunction[0] in [x for x in range(0,102)]+[999]:
                    print(xdr['display'], decodeFunction[1])
                    del xdr
                    return
                elif decodeFunction[0] == 9999:
                    ethernet.decodeEthernet(xdr, raw[16:length])
                else:
                    decodeFunction[0](xdr,raw[8:length],False)
    return

ipPortProtocol = {}

wellKnownPort = [16611,3784,2785,257,161,50000,137,80,8000,3478,5355,520,1228,1229,50010,50011,138,67,68]          # BFD, BFD control,Secure Electronic Transaction,SNMP,5000,
    # NetBIOS Name Service,QUIC (Quick UDP Internet Connections),QUIC,STUN,LLMNR,RIP,RTP,RTCP,RTP,RTCP,NetBIOS Datagram Service
    # DHCP Client, DHCP Server

sipRequest = r'(ACK|BYE|CANCEL|INFO|INVITE|MESSAGE|NOTIFY|OPTIONS|PRACK|REFER|REGISTER|SUBSCRIBE|UPDATE)\s[^\s]+\sSIP/2.0'
sipStatus = r'SIP/2.0\s+(\d{3})\s\b\w+'
regexSIPRequest = re.compile(sipRequest)
regexSIPStatus = re.compile(sipStatus)