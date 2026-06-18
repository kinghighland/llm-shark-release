import sys
import os
import struct
import base64
import datetime
import binascii
import pcap
import status
import diameter
import re
import sip
import ldap
import http2
import hpack
from collections import Counter

httpRequest = r'(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)\s([^\s]+)\sHTTP/1.1'
httpStatus = r'HTTP/1.1\s+(\d{3})\s\b([^\r]+)\r'
regexHTTPRequest = re.compile(httpRequest)
regexHTTPStatus = re.compile(httpStatus)


def buildTCPDecode(xdr,raw):
    # check Diameter
    if xdr['dport'] in diameterPortList or xdr['sport'] in diameterPortList:
        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (diameter.decodeTCPDIAMETER,'Well known port Diameter')
        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (diameter.decodeTCPDIAMETER,'Well known port Diameter')
        return (diameter.decodeTCPDIAMETER,'Well known port Diameter')
    found = True
    i = 0
    rawLength = len(raw)
    nextByte = struct.unpack('!B',raw[i:i+1])[0]
    if nextByte == 1 and rawLength > 28:
        version,len1,len2,flag,cc1,cc2,appid,h2h,e2e = struct.unpack('!BBHBBH3I',raw[0:20])
        length = len1*65536+len2          
        if length < 5*1500 and length != 0:
            if cc1 == 0:
                r = flag >> 7
                i += 20
                while i < rawLength-8:
                    avpCode,avp = struct.unpack('!2I',raw[i:i+8])
                    avpFlag = avp >> 24
                    avpLength = (((avp & 0xFFFFFF)+3)//4)*4
                    if avpLength == 0:
                        break
                    avpPadLength = avpLength - (avp & 0xFFFFFF)
                    if avpCode >> 16 != 0:
                        found = False
                        break
                    i += avpLength
                if found == True:
                    if r == 1:
                        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (diameter.decodeTCPDIAMETER,'Found port Diameter')
                    else:
                        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (diameter.decodeTCPDIAMETER,'Found port Diameter')
                    return (diameter.decodeTCPDIAMETER,'Found port Diameter')

    # check SIP
    if xdr['dport'] in sipPortList or xdr['sport'] in sipPortList:
        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (sip.decodeTCPSIP,'Well known port SIP')
        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (sip.decodeTCPSIP,'Well known port SIP')
        return (sip.decodeTCPSIP,'Well known port Diameter')
    try:
        string = raw[:200].decode()
        m = regexSIPRequest.match(string)
        if m != None:
            ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (sip.decodeTCPSIP,'Found port SIP')
            return (sip.decodeTCPSIP,'Found port SIP')
        else:
            m = regexSIPStatus.match(string)
            if m != None:
                ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (sip.decodeTCPSIP,'Found port SIP')
                return (sip.decodeTCPSIP,'Found port SIP')
    except Exception as err:
        pass

    # check HTTP2
    if(len(raw)>=24):
        if struct.unpack('24s',raw[:24])[0] == http2.HTTP2_PREFACE:
            ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (http2.decodeHTTP2,'Found port HTTP2')
            ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (http2.decodeHTTP2,'Found port HTTP2')
            return (http2.decodeHTTP2,'Found port HTTP2')
    if(len(raw)>=9):
        pos = 0
        length = struct.unpack('!H',raw[pos:pos+2])[0]*256 + struct.unpack('!B',raw[pos+2:pos+3])[0]
        header_type = struct.unpack('!B',raw[pos+3:pos+4])[0]
        flag_type = struct.unpack('!B',raw[pos+4:pos+5])[0]
        stream_identifier = struct.unpack('!I',raw[pos+5:pos+9])[0]
        padded = (flag_type >> 3) & 1
        end_header = (flag_type >> 2) & 1
        end_stream = flag_type & 1
        priority = (flag_type >> 5) & 1
        if(header_type in range(11)):
            ddd = hpack.hpack.Decoder()
            try:
                hhh = ddd.decode(raw[pos+9:pos+9+length])
                ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (http2.decodeHTTP2,'Found port HTTP2')
                ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (http2.decodeHTTP2,'Found port HTTP2')
                return (http2.decodeHTTP2,'Found port HTTP2')
            except:
                pass

    # check HTTP/1.1
    line1_pos = raw.find(b'\r\n')
    is_http1 = False
    if(line1_pos != -1):
        try:
            line1 = raw[:line1_pos].decode()
            request = regexHTTPRequest.match(line1)
            if request:
                is_http1 = True
            else:
                status1 = regexHTTPStatus.match(line1)
                if status1:
                    is_http1 = True
        except:
            is_http1 = False
    if is_http1 == True:
        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (http2.decodeHTTP1,'Found port HTTP1')
        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (http2.decodeHTTP1,'Found port HTTP1')
        return (http2.decodeHTTP1,'Found port HTTP1')

    # check LDAP
    if xdr['dport'] == 16611 or xdr['sport'] == 16611:
        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (ldap.decodeLDAP,'Well known port LDAP')
        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (ldap.decodeLDAP,'Well known port LDAP')
        return (ldap.decodeLDAP,'Well known port LDAP')

    # Others
    if xdr['sport'] in wellKnownPort:
        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (999,'Well known port'+str(xdr['sport']))
        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (999,'Well known port'+str(xdr['sport']))
        return (999,'Well known port'+str(xdr['sport']))
    if xdr['dport'] in wellKnownPort:
        ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (999,'Well known port'+str(xdr['dport']))
        ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (999,'Well known port'+str(xdr['dport']))
        return (999,'Well known port'+str(xdr['dport']))

    socket1Count = ipPortProtocol.get((xdr['sip'][len(xdr['sip'])-1],xdr['sport']),(0,'Not found port in tcpPortProtocol'))
    socket2Count = ipPortProtocol.get((xdr['dip'][len(xdr['dip'])-1],xdr['dport']),(0,'Not found port in tcpPortProtocol'))
    socket1Count_0 = socket1Count[0] + 1
    socket2Count_0 = socket2Count[0] + 1
    ipPortProtocol[(xdr['sip'][len(xdr['sip'])-1],xdr['sport'])] = (socket1Count_0,'Unkown port counted'+str(socket1Count_0))
    ipPortProtocol[(xdr['dip'][len(xdr['dip'])-1],xdr['dport'])] = (socket2Count_0,'Unkown port counted'+str(socket2Count_0))
    return (socket1Count_0,'Unkown port counted'+str(socket1Count_0))          # Unknown Protocol

def decodeTCP(xdr,raw):
    '''found = status.tcp_dup_list_1.get((raw,'_'.join(str(xdr['sip'])),'_'.join(str(xdr['dip']))),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup TCP Packet')
            return
        else:
            xdr['dup'] = True
    found = status.tcp_dup_list_2.get((raw,'_'.join(str(xdr['sip'])),'_'.join(str(xdr['dip']))),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup TCP Packet')
            return
        else:
            xdr['dup'] = True
    found = status.tcp_dup_list_3.get((raw,'_'.join(str(xdr['sip'])),'_'.join(str(xdr['dip']))),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup TCP Packet')
            return
        else:
            xdr['dup'] = True
    status.tcp_dup_list_3 = status.tcp_dup_list_2
    status.tcp_dup_list_2 = status.tcp_dup_list_1
    status.tcp_dup_list_1 = {}
    status.tcp_dup_list_1[(raw,'_'.join(str(xdr['sip'])),'_'.join(str(xdr['dip'])))] = xdr['ts']'''

    xdr['display'] += ', TCP'
    xdr['Level'] += 1
    if len(raw) < 13:
        del xdr
        del raw
        return
    sport,dport,seq,ack,headerByte = struct.unpack('!2H2IB',raw[:13])

    tcpHeaderLength = headerByte>>4
    tcpPayloadLength = len(raw) - tcpHeaderLength*4
    if tcpPayloadLength == 0:
        print(xdr['display'], ' tcpPayloadLength is 0')
        del xdr
        return

    xdr['sport'] = sport
    xdr['dport'] = dport
    if xdr.get('sport1', '') == '': xdr['sport1'] = sport
    if xdr.get('dport1', '') == '': xdr['dport1'] = dport
    xdr['seq'] = seq
    xdr['tcpPayloadLength'] = tcpPayloadLength

    decodeFunction1 = ipPortProtocol.get((xdr['sip'][-1],xdr['sport']),(0,'Not found port in tcpPortProtocol'))
    if decodeFunction1[0] not in [x for x in range(0,102)]+[999]:
        decodeFunction1[0](xdr,raw[tcpHeaderLength*4:],False)
    else:
        decodeFunction2 = ipPortProtocol.get((xdr['dip'][-1],xdr['dport']),(0,'Not found port in tcpPortProtocol'))
        if decodeFunction2[0] not in [x for x in range(0,102)]+[999]:
            decodeFunction2[0](xdr,raw[tcpHeaderLength*4:],False)
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
                decodeFunction = buildTCPDecode(xdr,raw[tcpHeaderLength*4:])
                if decodeFunction[0] == 999:
                    print(xdr['display'],decodeFunction[1])
                    del xdr
                    return
                elif decodeFunction[0] in [x for x in range(0,102)]+[999]:
                    print(xdr['display'], ' Unknown Protocol',xdr['id'])
                else:
                    decodeFunction[0](xdr,raw[tcpHeaderLength*4:],False)

    return

ipPortProtocol = {}

diameterPortList = [3868]
sipPortList = [5060]

tcpBufferList = {}
tcpList = {}
wellKnownPort = [16611,3784,3785,257,161,50000,22]          # BFD, BFD control,Secure Electronic Transaction,SNMP,50000,ssh,http

sipRequest = r'(ACK|BYE|CANCEL|INFO|INVITE|MESSAGE|NOTIFY|OPTIONS|PRACK|REFER|REGISTER|SUBSCRIBE|UPDATE)\s[^\s]+\sSIP/2.0'
sipStatus = r'SIP/2.0\s+(\d{3})\s\b\w+'
regexSIPRequest = re.compile(sipRequest)
regexSIPStatus = re.compile(sipStatus)
