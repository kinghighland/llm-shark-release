import sys
import os
import struct
import base64
import datetime
import time
import binascii
import xdrlib
from xml.dom.expatbuilder import FragmentBuilder
from xml.etree.ElementTree import ProcessingInstruction
import pcap
import re
from socket import inet_ntop, AF_INET6, inet_ntoa 
import status
import ipaddress
from string import printable
from collections import Counter
import inspect

sms_code_dict = {0x01: 'RP-DATA (DL)', 0x02: 'RP-ACK (UL)', 0x03: 'RP-ACK (DL)', 0x04: 'RP-ERROR (UL)', 0x05: 'RP-ERROR (DL)', 0x06: 'RP-SMMA (UL)',}
p = [x for x in printable.encode()]

def loadIPcfg(line):
    """Parse a seq.ipcfg line like 'AS=10.0.0.1,10.0.0.2' and add IPs to the corresponding list."""
    global asIP, scscfIP, mgcfIP, sbcIP, bgcfIP, icscfIP
    m = re.match(r'(\w+)=(.*)', line.strip())
    if not m:
        return
    key = m.group(1).upper()
    ips_str = m.group(2).strip()
    if not ips_str:
        return
    ip_list = [ip.strip() for ip in ips_str.split(',') if ip.strip()]
    if key == 'AS':
        asIP.extend(ip_list)
    elif key == 'SCSCF':
        scscfIP.extend(ip_list)
    elif key == 'MGCF':
        mgcfIP.extend(ip_list)
    elif key == 'SBC':
        sbcIP.extend(ip_list)
    elif key == 'BGCF':
        bgcfIP.extend(ip_list)
    elif key == 'ICSCF':
        icscfIP.extend(ip_list)

def get_sdp_info(sdpHeader):
    Audio = False
    Audio_a = ""
    Video = False
    Video_a = ""
    for property in sdpHeader:
        if(property[:len('m=audio 0')] == 'm=audio 0'):
            Audio = True
            Audio_a = 'SDP.Audio=closed'
            Video = False
        elif(property[:len('m=video 0')] == 'm=video 0'):
            Video = True
            Video_a = 'SDP.Video=closed'
            Audio = False
        elif(property[:len('m=audio')] == 'm=audio'):
            Audio = True
            Video = False
        elif(property[:len('m=video')] == 'm=video'):
            Video = True
            Audio = False
        elif(Audio == True):
            if(property[:len('a=sendrecv')] == 'a=sendrecv'):
                Audio_a =  'SDP.Audio=sendrecv'
            elif(property[:len('a=sendonly')] == 'a=sendonly'):
                Audio_a =  'SDP.Audio=sendonly'
            elif(property[:len('a=recvonly')] == 'a=recvonly'):
                Audio_a =  'SDP.Audio=recvonly'
            elif(property[:len('a=inactive')] == 'a=inactive'):
                Audio_a =  'SDP.Audio=inactive'
        elif(Video == True):
            if(property[:len('a=sendrecv')] == 'a=sendrecv'):
                Video_a =  'SDP.Video=sendrecv'
            elif(property[:len('a=sendonly')] == 'a=sendonly'):
                Video_a =  'SDP.Video=sendonly'
            elif(property[:len('a=recvonly')] == 'a=recvonly'):
                Video_a =  'SDP.Video=recvonly'
            elif(property[:len('a=inactive')] == 'a=inactive'):
                Video_a =  'SDP.Video=inactive'

    if(Video_a != ""):
        return Video_a
    else:
        return Audio_a

def decodeUDPSIP(xdr,raw,flush):
    decodeSIP(xdr,raw,False,True)

def to_string(raw):
    try:
        sip_header_string = raw.decode()
    except:
        raw1 = bytearray(raw)
        length_raw = len(raw1)
        for n in range(length_raw):
            if raw1[n] not in p:
                raw1[n] = 95             # convert a non printable charactor to a "_".
        sip_header_string = raw1.decode()
    return sip_header_string

def matchSIPHeader(raw):
    string1 = to_string(raw)
    fragHeader = False
    content_length = -1
    m = regexSIPRequest.match(string1)
    if m != None:
        fragHeader = True
    else:
        m = regexSIPStatus.match(string1)
        if m != None:
            fragHeader = True
        else:
            fragHeader = False
    if(fragHeader == True):
        content_length_match = re.search('\r\n(Content-Length|l)\s*:\s*(.*)',string1)
        if content_length_match:
            content_length = int(content_length_match.groups()[-1].strip())
    return fragHeader, content_length 

def checkSIPPacket(raw):
    is_fragments = False        # wether the packet is partial sip messages?
    sip_message_list = []

    while True:
        header_raw, sep, Body_raw = raw.partition(b"\r\n\r\n")
        if(sep == b'\r\n\r\n'):
            fragHeader, content_length = matchSIPHeader(header_raw)
            if(fragHeader == True and content_length <= len(Body_raw)):
                sip_message_list.append(header_raw +sep+ Body_raw[:content_length])
                raw = Body_raw[content_length:]
                if(len(raw) == 0):
                    is_fragments = False
                    fragHeader = True
                    break
            elif(fragHeader == True and content_length > len(Body_raw)):
                return True, []
            else:
                is_fragments = True
                break
        else:
            is_fragments = True
            break

    return is_fragments,sip_message_list

def checkSIPPacket_flush(raw):
    is_fragments = False        # wether the packet is partial sip messages?
    sip_message_list = []

    while True:
        header_raw, sep, Body_raw = raw.partition(b"\r\n\r\n")
        if(sep == b'\r\n\r\n'):
            fragHeader, content_length = matchSIPHeader(header_raw)
            if(fragHeader == True and content_length <= len(Body_raw)):
                sip_message_list.append(header_raw +sep+ Body_raw[:content_length])
                raw = Body_raw[content_length:]
                if(len(raw) == 0):
                    is_fragments = False
                    fragHeader = True
                    break
            elif(fragHeader == True and content_length > len(Body_raw)):
                sip_message_list.append(header_raw +sep+ Body_raw)
                break
            else:
                is_fragments = True
                sip_message_list.append(raw)
                break
        else:
            is_fragments = True
            sip_message_list.append(raw)
            break

    return is_fragments,sip_message_list

def checkTCPSIPFrags(xdr):
    key = ','.join(['_'.join(str(xdr['sip'])),str(xdr['sport']),''.join(str(xdr['dip'])),str(xdr['dport'])])
    frag_list = tcpsipFrags[key]
    if(len(frag_list) == 1):
        return None, []
    else:
        sorted_frag_list = sorted(frag_list, key = lambda x: x['xdr']['seq'])
        trunk_list = [[]]
        trunk_list[0].append(sorted_frag_list[0])
        for trunk in sorted_frag_list[1:]:
            if(trunk_list[-1][-1]['xdr']['seq']+len(trunk_list[-1][-1]['raw']) == trunk['xdr']['seq']):
                trunk_list[-1].append(trunk)
        for n in trunk_list:
            if(xdr in [x['xdr'] for x in n]):
                is_fragments,sip_message_list = checkSIPPacket(b"".join([x['raw'] for x in n]))
                if(is_fragments == False):
                    xdr = n[0]['xdr']
                    RawData, RawData1 = [], []
                    for x in n:
                        RawData = RawData + x['xdr']['RawData']
                        RawData1 = RawData1 + x['xdr']['RawData1']
                    xdr['RawData'] = RawData
                    xdr['RawData1'] = RawData1
                    xdr['frags'] = [x['xdr']['id'] for x in n]
                    return xdr, sip_message_list
                break
        return None, []

def decodeTCPSIP(xdr,raw,flush):
    is_fragments,sip_message_list = checkSIPPacket(raw)
    if(is_fragments):
        tcpsipFrags.setdefault(','.join(['_'.join(str(xdr['sip'])),str(xdr['sport']),''.join(str(xdr['dip'])),str(xdr['dport'])]),[]).append({"xdr": xdr, "raw":raw})
        print(xdr['display'],'SIP Fragment')
        xdr, sip_message_list = checkTCPSIPFrags(xdr)
        if(xdr != None):
            for sip_raw in sip_message_list:
                tempXDR = xdr.copy()
                decodeSIP(tempXDR,sip_raw,False,True)
            frag_list = xdr.get('frags',[xdr['id']])
            temp_list = []
            key_list = []
            for key in tcpsipFrags:
                for n in tcpsipFrags[key]:
                    if(n['xdr']['id'] not in frag_list):
                        temp_list.append(n)
                if(len(temp_list) == 0):
                    key_list.append(key)
                else:
                    tcpsipFrags[key] = temp_list
                temp_list = []
            [tcpsipFrags.pop(x) for x in key_list]
            
    else:
        for sip_raw in sip_message_list:
            tempXDR = xdr.copy()
            decodeSIP(tempXDR,sip_raw,False,True)
        del xdr

def flush_tcp_sip():
    for key in tcpsipFrags:
        for record in tcpsipFrags[key]:
            if(len(record['xdr']['RawData']) == 1):
                pos = record['xdr']['RawData'][0].find(record['raw'])
                if(pos >=0):
                    raw = record['xdr']['RawData'][0][pos:]
                    is_fragments,sip_message_list = checkSIPPacket_flush(raw)
                    for sip_raw in sip_message_list:
                        tempXDR = record['xdr'].copy()
                        decodeSIP(tempXDR,sip_raw,False,True)
                    del record['xdr']
                else:
                    is_fragments,sip_message_list = checkSIPPacket_flush(record['raw'])
                    for sip_raw in sip_message_list:
                        tempXDR = record['xdr'].copy()
                        decodeSIP(tempXDR,sip_raw,False,True)
                    del record['xdr']
            else:
                is_fragments,sip_message_list = checkSIPPacket_flush(record['raw'])
                for sip_raw in sip_message_list:
                    tempXDR = record['xdr'].copy()
                    decodeSIP(tempXDR,sip_raw,False,True)
                del record['xdr']

def flush_udp_sip():
    for key in udpSipFrags:
        for record in udpSipFrags[key]:
            decodeSIP(record['xdr'],record['raw'],False,True)

def decodeSCTPSIP(xdr,raw,flush):
    decodeSIP(xdr,raw,flush,False)

def decodeSIP(xdr,raw,flush,fragHeader):
    global lastUpdateTime
    xdr['display'] += ', SIP'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','4'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,None,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'0',''
    xdr['ip'] = 0
    xdr['msisdn'] = 0
    xdr['keyword4'] = ""
    xdr['tid'] = ''
    xdr['tac'] = ''
    xdr['SuccFlag'] = ''
    xdr['prcType'] = ''
    xdr['Timeout'] = ''
    xdr['Retrs'] = ''
    xdr['mode'] = 'None'
    xdr['keyword1'] = ''
    splitPos = raw.find(b'\r\n\r\n')
    if splitPos == -1:
        splitPos = len(raw)

    raw1 = bytearray(raw[:splitPos])
    length_raw = len(raw1)
    for n in range(length_raw):
        if raw1[n] not in p:
            raw1[n] = 95
    string = raw1.decode()
    m = regexSIPRequest.match(string)
    request = ''
    status1 = ''
    if m != None:
        msgType = 0                           # 0: sip request, 1: sip status1
        xdr['RequestMethod'] = m.group(1)
        xdr['msgType'] = msgType
        request = m.group(1)
        # dumy keyword1
    else:
        m = regexSIPStatus.match(string)
        if m != None:
            msgType = 1                       # 0: sip request, 1: sip status1
            
            xdr['Cause'] = int(m.group(1))
            xdr['RequestMethod'] = ''
            status1 = m.group(1)
            status2 = m.group(2)
            xdr['msgType'] = msgType
    if xdr.get('RequestMethod',0) == 0:
        return
    xdr['RequestURI'] = ''
    xdr['Sender'] = ''
    xdr['Receiver'] = ''
    xdr['CallID'] = ''
    xdr['CSeq'] = ''
    xdr['ContentType'] = ''
    xdr['calling'] = ''
    xdr['called'] = ''
    xdr["Target_Dialog"],xdr['P_Early_Media'], xdr["P_Preferred_Identity"], xdr["P_Asserted_Identity"], xdr["P_Access_Network_Info"], xdr["P_Charging_Vector"], xdr["P_Called_Party_ID"],  xdr["Record_Route"], xdr["contact"], xdr["Security_Server"], xdr["Security_Client"], xdr["Security_Verify"], xdr["Max_Forwards"], xdr["Authorization"], xdr["nonce"], xdr["Session_ID"] = ['']*16
    xdr["Content_Length"] = ''
    xdr['Via'] = ''
    xdr['branch'] = ''
    xdr['branch_count'] = 0
    xdr["Route"] = ''
    xdr['interface'] = None
    xdr['dir'] = None

    sipHeader = string[:splitPos].split('\r\n')

    # Get the SIP header fields

    sip_header_compact = []
    current_header = sipHeader[0]
    for line in sipHeader[1:]:
        if(line == '' or line[0] == " " or line[0] == "\t"):
            current_header = current_header + line
        else:
            sip_header_compact.append(current_header)
            current_header = line
    if(current_header != ''):
        sip_header_compact.append(current_header)

    for line in sip_header_compact:
        if xdr['RequestURI'] == '':
            m = regexRequestURI.match(line)
            if m:
                xdr['RequestURI'] = m.group(1)
                continue
        if xdr['Receiver'] == '':
            m = regexHeaderTo.match(line)
            if m:
                xdr['Receiver'] = re.sub('"','\'',m.group(1))
                try:
                    xdr['called'] = re.search(r'(tel|sip):[+]?([\d*]+)', xdr['Receiver'],flags=re.I).group(2)
                except:
                    xdr['called'] = ""
                continue
        if xdr['Sender'] == '':
            m = regexHeaderFrom.match(line)
            if m:
                xdr['Sender'] = re.sub('"','\'',m.group(1))
                try:
                    xdr['calling'] = re.search(r'(tel|sip):[+]?([\d*]+)', xdr['Sender'],flags=re.I).group(2)
                except:
                    xdr['calling'] = ""
                continue
        m = regexHeaderCallID.match(line)
        if xdr['CallID'] == '':
            if m:
                xdr['CallID'] = m.group(1)
                continue
        if xdr['CSeq'] == '':
            m = regexHeaderCSeq.match(line)
            if m:
                xdr['CSeq'] = m.group(1)
                continue
        if xdr['ContentType'] == '':
            m = regexHeaderContentType.match(line)
            if m:
                xdr['ContentType'] = m.group(1)
                continue
        if xdr['P_Preferred_Identity'] == '':
            m = regexHeader_P_Preferred_Identity.match(line)
            if m:
                xdr['P_Preferred_Identity'] = m.group(1)
                continue
        if xdr['P_Asserted_Identity'] == '':
            m = regexHeader_P_Asserted_Identity.match(line)
            if m:
                xdr['P_Asserted_Identity'] = m.group(1)
                continue
        if xdr['P_Access_Network_Info'] == '':
            m = regexHeader_P_Access_Network_Info.match(line)
            if m:
                xdr['P_Access_Network_Info'] = m.group(1)
                continue
        if xdr['P_Charging_Vector'] == '':
            m = regexHeader_P_Charging_Vector.match(line)
            if m:
                xdr['P_Charging_Vector'] = m.group(1)
                continue
        if xdr['P_Early_Media'] == '':
            m = regexHeader_PEM.match(line)
            if m:
                xdr['P_Early_Media'] = m.group(1)
                continue

        if xdr['Session_ID'] == '':
            m = regexHeader_Session_ID.match(line)
            if m:
                xdr['Session_ID'] = m.group(1)
                continue

        if xdr['P_Called_Party_ID'] == '':
            m = regexHeader_P_Called_Party_ID.match(line)
            if m:
                xdr['P_Called_Party_ID'] = m.group(1)
                continue
        if xdr['Route'] == '':
            m = regexHeader_Route.match(line)
            if m:
                xdr['Route'] = m.group(1)
                continue
        else:
            m = regexHeader_Route.match(line)
            if m:
                xdr['Route'] = xdr['Route'] + ',' + m.group(1)
                continue
        if xdr['Via'] == '':
            m = regexHeader_via.match(line)
            if m:
                xdr['Via'] = m.group(1)
                continue
        else:
            m = regexHeader_via.match(line)
            if m:
                xdr['Via'] = xdr['Via'] + ',' + m.group(1)
                continue
        if xdr['Record_Route'] == '':
            m = regexHeader_Record_Route.match(line)
            if m:
                xdr['Record_Route'] = m.group(1)
                continue
        if xdr['contact'] == '':
            m = regexHeader_Contact.match(line)
            if m:
                xdr['contact'] = m.group(1)
                continue
        if xdr['Security_Server'] == '':
            m = regexHeader_Security_Server.match(line)
            if m:
                xdr['Security_Server'] = m.group(1)
                continue
        if xdr['Security_Client'] == '':
            m = regexHeader_Security_Client.match(line)
            if m:
                xdr['Security_Client'] = m.group(1)
                continue
        if xdr['Security_Verify'] == '':
            m = regexHeader_Security_Verify.match(line)
            if m:
                xdr['Security_Verify'] = m.group(1)
                continue
        if xdr['Content_Length'] == '':
            m = regexheaderLength.match(line)
            if m:
                try:
                    xdr['Content_Length'] = int(m.group(1))
                except:
                    pass
                continue
        if xdr['Max_Forwards'] == '':
            m = regexHeader_Max_Forwards.match(line)
            if m:
                if m.group(1).isdecimal():
                    xdr['Max_Forwards'] = int(m.group(1))
                else:
                    xdr['Max_Forwards'] = 0
                continue
        if xdr['Authorization'] == '':
            m = regexHeader_Authorization.match(line)
            if m:
                xdr['Authorization'] = m.group(1)
                m = regexHeader_Nonce.search(xdr['Authorization'])
                if m:
                    xdr['nonce'] = m.group(1)
                continue
        if xdr['Target_Dialog'] == '':
            m = regexHeader_Target_Dialog.match(line)
            if m:
                xdr['Target_Dialog'] = m.group(1)
                continue

    xdr['branch_count'] = len(re.findall('branch=',xdr['Via']))
    xdr['branch'] = '|'.join([x.split(';')[0] for x in re.findall('branch=[^,]+',xdr['Via'])])
    xdr['Routes'] = xdr['Route'].split(',')
    
    sdp_info = None
    if(xdr['Content_Length'] == 0):
        body = ''
    else:
        body = raw[splitPos + 2:]
        if(len(body)>2):
            if(xdr['ContentType'] == 'application/sdp'):
                try:
                    sdpHeader = body.decode().split('\r\n')[2:]
                    sdp_info = get_sdp_info(sdpHeader)
                except:
                    sdp_info = None
            elif(xdr['ContentType'] == 'message/sip'):
                sdp_info = '<sip>'
            elif(body[2] in (0x00,0x01,0x02,0x03,0x04,0x05,0x06,)):
                sdp_info = sms_code_dict.get(body[2])
            elif(body[2:7] == b'<?xml'):
                sdp_info = '<xml>'
            elif(body[2:4] == b'--'):
                sdp_info = '<MIME>'
            else:
                m = re.search('SIP/2.0',body.decode())
                if m:
                    m = regexSIPRequest.match(body.decode())
                    if m != None:
                        request = ''
                        status1 = ''
                        sdp_info = m.group(1)
                    else:
                        m = regexSIPStatus.match(body.decode())
                        if m != None:
                            request = ''
                            status1 = ''
                            sdp_info = m.group(1)
                else:
                    sdp_info = '<sip>'

    p_list = []
    if(status1 != ""):
        if xdr['P_Early_Media'] in ("sendrecv","sendonly","recvonly","inactive"):
            p_list.append("PEM")
        p_list.append(xdr['CSeq'].lower())
        if(sdp_info != "" and sdp_info != None):
            p_list.append(sdp_info)

        if(p_list == [''] or p_list == []):
            xdr['keyword1'] = 'SIP '+str(status1)+' '+status2
        else:
            xdr['keyword1'] = 'SIP '+str(status1)+' '+status2+'('+", ".join(p_list)+')'

    elif(request != ''):
        if(str(xdr['Max_Forwards']) != ""):
            p_list.append('MF='+str(xdr['Max_Forwards']))
        if xdr['P_Early_Media'] in ("sendrecv","sendonly","recvonly","inactive"):
            p_list.append("PEM")
        p_list.append(xdr['CSeq'].lower())
        if(sdp_info != "" and sdp_info != None):
            p_list.append(sdp_info)
        
        # p_list.append(xdr['CallID'][:9]+"..."+xdr['CallID'][-3:])      # comment out this call-id field.
        if(p_list == [''] or p_list == []):
            xdr['keyword1'] = request
        else:
            xdr['keyword1'] = request +'('+", ".join(p_list)+')'

    # eSRVCC -> SIP INVITE

    if xdr['RequestMethod'] == 'INVITE':
        m = re.search(r'<tel:[+]?(\d+)>',xdr['Receiver'],flags=re.I)
        xdr['ts1'] = xdr['ts'][0] * 1000000000 + xdr['ts'][1]
        if len(status.callFlow) == 0:
            status.callFlow = [xdr]
        else:  
            status.callFlow.append(xdr)
        if m:
            msisdn = m.group(1)
            stn_sr = status.stnSRIMSI.get(msisdn,(0,0))
            if stn_sr != (0,0):
                m = re.search(str(stn_sr[1]),xdr['Sender'])
                if m:
                    xdr['imsi'] = stn_sr[0]
                    xdr['msisdn'] = stn_sr[1]
                    callidIMSI[xdr['CallID']] = (xdr['imsi'],stn_sr[1])


    if status1 == r'401' or status1 == r'403':
        xdr['dir'] = '1'
    elif request == r'REGISTER':
        xdr['dir'] = '0'

    xdr['request'] = request
    xdr['status1'] = status1

    if(len(xdr.get('frags',[])) > 1):
        print(xdr['display'], 'Frags: ('+', '.join(['#{}'.format(x) for x in xdr['frags']])+")",request,status1)
    else:
        print(xdr['display'],request,status1)
    status.sipXDR.append(xdr)

def find_registration(regist_list):
    for xdr in regist_list:
        # REGISTER interface and dir
        # 没有P-Charging-Vector	Gm/GmOverGTP
        # 有P-Charging-Vector and branch==1 and Content-Length == 0	Mw1
        # 有P-Charging-Vector and branch==2 and Content-Length == 0	Mw3
        # 有P-Charging-Vector and Content-Length != 0	ISC
        # 有P-Charging-Vector and Max-Forwards == 69 and Content-Length == 0	Mw1
        # 有P-Charging-Vector and Max-Forwards == 68 and Content-Length == 0	Mw3
        # 有P-Charging-Vector and 有ims标准请求 and Content-Length == 0	Mw1
        # 有P-Charging-Vector and 有scscf and Content-Length == 0	Mw3
        if(xdr['RequestMethod'] == 'REGISTER' and xdr.get('P_Charging_Vector','') == '' and xdr.get('Content_Length',0) == 0):
            if(xdr.get('gtp',False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
            else:
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
            xdr['dir'] = '0'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in ueIP:      ueIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in sbcRanIP:  sbcRanIP.append(xdr['dip'][-1])
        # Security-Client on Gm interface
        elif(xdr['RequestMethod'] == 'REGISTER' and xdr['Security_Client'] != '' and xdr.get('Content_Length',0) == 0):
            if(xdr.get('gtp',False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
            else:
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
            xdr['dir'] = '0'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in ueIP:      ueIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in sbcRanIP:  sbcRanIP.append(xdr['dip'][-1])
        elif(xdr['RequestMethod'] == 'REGISTER' and (xdr.get('gtp',False) == True or xdr.get('esp',False) == True) and xdr.get('Content_Length',0) == 0):
            if(xdr.get('gtp',False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
            else:
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
            xdr['dir'] = '0'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in ueIP:      ueIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in sbcRanIP:  sbcRanIP.append(xdr['dip'][-1])
        # 有P-Charging-Vector and branch==1 and Content-Length == 0	Mw1
        elif(xdr['RequestMethod'] == 'REGISTER' and  xdr.get('P_Charging_Vector','') != '' and xdr.get('branch_count',0) == 1 and xdr.get('Content_Length',0) == 0):
            xdr['interface'] = 'Mw1'
            xdr['dir'] = '0'
            xdr['msgType'] = 1025
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in sbcCoreIP:     sbcCoreIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in icscfIP:       icscfIP.append(xdr['dip'][-1])
        # 有P-Charging-Vector and branch==2 and Content-Length == 0	Mw3
        elif(xdr['RequestMethod'] == 'REGISTER' and  xdr.get('P_Charging_Vector','') != '' and xdr.get('branch_count',0) == 2 and xdr.get('Content_Length',0) == 0 and len(xdr['sip'][-1]) == 4):
            xdr['interface'] = 'Mw3'
            xdr['dir'] = '1'
            xdr['msgType'] = 1063
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in icscfIP:       icscfIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
        # 有P-Charging-Vector and Content-Length != 0	ISC
        elif(xdr['RequestMethod'] == 'REGISTER' and xdr.get('Content_Length',0) != 0 and len(xdr['sip'][-1]) == 4):
            xdr['keyword4'] = tag_as(xdr.get('Routes',[""])[0])
            xdr['interface'] = 'ISC'
            xdr['dir'] = '0'
            xdr['msgType'] = 1021
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in scscfIP:       scscfIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in asIP:          asIP.append(xdr['dip'][-1])
        # 有P-Charging-Vector and Max-Forwards == 69 and Content-Length == 0	Mw1
        elif(xdr['RequestMethod'] == 'REGISTER' and xdr.get('Max_Forwards',0) == 69 and xdr.get('Content_Length',0) == 0 and len(xdr['sip'][-1]) == 4):
            xdr['interface'] = 'Mw1'
            xdr['dir'] = '0'
            xdr['msgType'] = 1025
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in sbcCoreIP:     sbcCoreIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in icscfIP:       icscfIP.append(xdr['dip'][-1])
        # 有P-Charging-Vector and Max-Forwards == 68 and Content-Length == 0	Mw3
        elif(xdr['RequestMethod'] == 'REGISTER' and xdr.get('Max_Forwards',0) == 68 and xdr.get('Content_Length',0) == 0 and len(xdr['sip'][-1]) == 4):
            xdr['interface'] = 'Mw3'
            xdr['dir'] = '1'
            xdr['msgType'] = 1063
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in icscfIP:       icscfIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
        elif(xdr['RequestMethod'] == 'SUBSCRIBE' and len(xdr['sip'][-1]) == 4):
            m = re.search(r'scscf', xdr.get('Routes',[''])[0],flags=re.I)
            if m:
                m = re.search(r'atcf', xdr.get('P_Asserted_Identity',''),flags=re.I)
                if m:
                    xdr['interface'] = 'Mw2'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1061
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in sbcCoreIP:       sbcCoreIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in scscfIP:         scscfIP.append(xdr['dip'][-1])
                if(xdr.get('P_Asserted_Identity','') != '' and xdr.get('Max_Forwards',0) == 69):
                    xdr['interface'] = 'Mw2'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1061
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in sbcCoreIP:       sbcCoreIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in scscfIP:         scscfIP.append(xdr['dip'][-1])
                    
        else:
            m_scscf = temp = re.search(r'scscf',xdr['RequestURI'],flags=re.I)
            m_ims = temp = re.search(r'sip:ims.mnc',xdr['RequestURI'],flags=re.I)
            # 有P-Charging-Vector and 有scscf and Content-Length == 0	Mw3
            if(xdr['RequestMethod'] == 'REGISTER' and m_scscf and xdr.get('Content_Length',0) == 0 and len(xdr['sip'][-1]) == 4):
                xdr['interface'] = 'Mw3'
                xdr['dir'] = '1'
                xdr['msgType'] = 1063
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in icscfIP:       icscfIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
            # 有P-Charging-Vector and 有ims标准请求 and Content-Length == 0	Mw1
            elif(xdr['RequestMethod'] == 'REGISTER' and m_ims and xdr.get('Content_Length',0) == 0 and len(xdr['sip'][-1]) == 4):
                xdr['interface'] = 'Mw1'
                xdr['dir'] = '0'
                xdr['msgType'] = 1025
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in sbcCoreIP:     sbcCoreIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in icscfIP:       icscfIP.append(xdr['dip'][-1])

        # REGISTER IMSI
        if xdr['RequestMethod'] == 'REGISTER':
            m = re.match(r'<sip:(\d+)@ims\.mnc\d{3}\.mcc\d{3}\.3gppnetwork\.org>',xdr['Sender'])
            if m:
                xdr['imsi'] = m.group(1)
                callidIMSI[xdr['CallID']] = (xdr['imsi'],xdr['msisdn'])

    return

def tag_as(Route):
    result = ''
    m = re.search(r'kjas',Route,flags=re.I)
    if m:
        result = 'AS'
    m = re.search(r'print@',Route,flags=re.I)
    if m:
        result = 'AS'
    m = re.search(r'aspool',Route,flags=re.I)
    if m:
        result = 'AS'
    m = re.search(r'mmtel',Route,flags=re.I)
    if m:
        result = 'TEL-AS'
    m = re.search(r'volteas',Route,flags=re.I)
    if m:
        result = 'TEL-AS'
    m = re.search(r'voltetas',Route,flags=re.I)
    if m:
        result = 'TEL-AS'
    m = re.search(r'mtas',Route,flags=re.I)
    if m:
        result = 'TEL-AS'
    m = re.search(r'sccas',Route,flags=re.I)
    if m:
        result = 'SCC-AS'
    m = re.search(r'role=vcc;',Route,flags=re.I)
    if m:
        result = 'SCC-AS'
    m = re.search(r'scpas',Route,flags=re.I)
    if m:
        result = 'SCP-AS'
    m = re.search(r'cpcsas',Route,flags=re.I)
    if m:
        result = 'CPCS-AS'
    m = re.search(r'catas',Route,flags=re.I)
    if m:
        result = 'CAT-AS'
    m = re.search(r'.cat.',Route,flags=re.I)
    if m:
        result = 'CAT-AS'
    m = re.search(r'ctxas',Route,flags=re.I)
    if m:
        result = 'CTX-AS'
    m = re.search(r'ipsm',Route,flags=re.I)
    if m:
        result = 'SMS-AS'
    return result

def find_message(message_list):
    for line_no, xdr in enumerate(message_list):
        m = re.search(r'sip\s?:\s?smsc@ims\.mnc\d+\.mcc',xdr['RequestURI'],flags=re.I)
        if m:
            if(xdr['P_Asserted_Identity'] != ''):
                m_scscf = re.search(r'scscf',xdr['Routes'][0],flags=re.I)
                m_ipsm = re.search(r'ipsm',xdr['Routes'][0],flags=re.I)
                if m_scscf and len(xdr['sip'][-1]) == 4:
                    xdr['interface'] = 'Mw2'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1061
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in sbcCoreIP:     sbcCoreIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
                elif m_ipsm and len(xdr['sip'][-1]) == 4:
                    xdr['interface'] = 'ISC'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1021
                    xdr['mode'] = 'Complete'
                    xdr['keyword4'] = 'SMS-AS'
                    if xdr['sip'][-1] not in scscfIP:       scscfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in asIP:          asIP.append(xdr['dip'][-1])
                elif(xdr.get('Max_Forwards',0) == 69 and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'Mw2'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1061
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in sbcCoreIP:     sbcCoreIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
                elif(xdr.get('Max_Forwards',0) == 68 and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'ISC'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1021
                    xdr['mode'] = 'Complete'
                    xdr['keyword4'] = 'SMS-AS'
                    if xdr['sip'][-1] not in scscfIP:       scscfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in asIP:          asIP.append(xdr['dip'][-1])
            else:
                if(xdr.get('gtp', False)):
                    xdr['interface'] = 'GmOverGTP'
                    xdr['msgType'] = 1053
                    xdr['dir'] = '0'
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
                else:
                    xdr['interface'] = 'Gm'
                    xdr['msgType'] = 1015
                    xdr['dir'] = '0'
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
            
        else:
            if(xdr.get('P_Charging_Vector','') == '' and xdr.get('Routes',['']) != [''] and xdr.get('Security_Verify','') != ''):
                if(xdr.get('gtp', False)):
                    xdr['interface'] = 'GmOverGTP'
                    xdr['msgType'] = 1053
                    xdr['dir'] = '0'
                    xdr['mode'] = 'Complete'
                    if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
                    if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
                else:
                    xdr['interface'] = 'Gm'
                    xdr['msgType'] = 1015
                    xdr['dir'] = '0'
                    xdr['mode'] = 'Complete'
                    if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
                    if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
            elif(xdr.get('MF',0) != 70 and (xdr.get('P_Charging_Vector','') == '' or xdr.get('Routes',['']) == [''])):
                if(xdr.get('gtp', False)):
                    xdr['interface'] = 'GmOverGTP'
                    xdr['msgType'] = 1053
                    xdr['dir'] = '1'
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
                else:
                    xdr['interface'] = 'Gm'
                    xdr['msgType'] = 1015
                    xdr['dir'] = '1'
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
            else:
                m_scscf = re.search(r'scscf',xdr['Routes'][0],flags=re.I)
                m_ipsm = re.search(r'ipsm',xdr['Routes'][0],flags=re.I)
                if(xdr.get('branch',"") != "" and len(xdr['branch']) == 2 and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'Mw2'
                    xdr['dir'] = '1'
                    xdr['msgType'] = 1061
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in sbcCoreIP:     sbcCoreIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
                elif(xdr.get('branch',"") != "" and len(xdr['branch']) == 1 and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'ISC'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1021
                    xdr['mode'] = 'Complete'
                    xdr['keyword4'] = 'SMS-AS'
                    if xdr['sip'][-1] not in scscfIP:       scscfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in asIP:          asIP.append(xdr['dip'][-1])
                elif(xdr.get('Max_Forwards',0) == 70 and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'ISC'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1021
                    xdr['mode'] = 'Complete'
                    xdr['keyword4'] = 'SMS-AS'
                    if xdr['sip'][-1] not in scscfIP:       scscfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in asIP:          asIP.append(xdr['dip'][-1])
                elif(xdr.get('Max_Forwards',0) == 69 and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'Mw2'
                    xdr['dir'] = '1'
                    xdr['msgType'] = 1061
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in sbcCoreIP:     sbcCoreIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])

def find_ATCF_SCCAS_I2(invite_list):
    for line_no, xdr in enumerate(invite_list):
        if(xdr['Target_Dialog'] != ''):
            xdr['interface'] = 'ATCF-SCCAS'
            xdr['dir'] = '0'
            xdr['msgType'] = 1059
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in sbcCoreIP:     sbcCoreIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in SCCASIP:       SCCASIP.append(xdr['dip'][-1])
            status.sipStatus.setdefault('ATCF-SCCAS',[]).append(xdr['id'])
            
            m = re.search(r'atcf.*\.org',invite_list[line_no - 1]['Routes'][0],flags=re.I)
            if(m and len(invite_list[line_no - 1]['sip'][-1]) == 4):
                invite_list[line_no - 1]['interface'] = 'I2'
                invite_list[line_no - 1]['dir'] = '0'
                invite_list[line_no - 1]['msgType'] = 1051
                invite_list[line_no - 1]['mode'] = 'Complete'
                if invite_list[line_no - 1]['sip'][-1] not in eMSCIP:        eMSCIP.append(invite_list[line_no - 1]['sip'][-1])
                if invite_list[line_no - 1]['dip'][-1] not in sbcCoreIP:     sbcCoreIP.append(invite_list[line_no - 1]['dip'][-1])
                status.sipStatus.setdefault('I2',[]).append(xdr['id'])
            elif(line_no >=2 and invite_list[line_no - 1]['CallID'] == xdr['CallID'] and invite_list[line_no - 1]['Target_Dialog'] == '' and len(invite_list[line_no - 1]['sip'][-1]) == 4):
                invite_list[line_no - 1]['interface'] = 'I2'
                invite_list[line_no - 1]['dir'] = '0'
                invite_list[line_no - 1]['msgType'] = 1051
                invite_list[line_no - 1]['mode'] = 'Complete'
                if invite_list[line_no - 1]['sip'][-1] not in eMSCIP:        eMSCIP.append(invite_list[line_no - 1]['sip'][-1])
                if invite_list[line_no - 1]['dip'][-1] not in sbcCoreIP:     sbcCoreIP.append(invite_list[line_no - 1]['dip'][-1])
                status.sipStatus.setdefault('I2',[]).append(xdr['id'])

def find_mgcf(invite_list):
    for line_no, xdr in enumerate(invite_list):
        Is_Routes_masked = False
        m = re.search(r'FFFFFFFFFF|\*\*\*\*\*\*\*\*\*\*',xdr.get('Routes',[""])[0],flags=re.I)
        if m:
            Is_Routes_masked = True
        if(Is_Routes_masked == True):
            if(xdr['mode'] != 'Complete' and line_no + 3 < len(invite_list)):
                sip_1 = invite_list[line_no + 1]['sip'][-1]
                dip_2 = invite_list[line_no + 2]['dip'][-1]
                sip_2 = invite_list[line_no + 2]['sip'][-1]
                dip_3 = invite_list[line_no + 3]['dip'][-1]
                l_1 = len(invite_list[line_no + 1].get('Routes',[""])[0])
                l_2 = len(invite_list[line_no + 2].get('Routes',[""])[0])
                l_3 = len(invite_list[line_no + 3].get('Routes',[""])[0])
                g0 = re.search('GEN-ACCESS',xdr.get('P_Access_Network_Info',""))
                c0 = xdr.get('P_Charging_Vector',"")
                a0 = xdr.get('P_Asserted_Identity',"")
                
                if(a0 != "" and g0 != None and c0 == "" and sip_2 == dip_3 and l_1 < l_2 and l_2 > l_3 and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'Mg1'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1023
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in mgcfIP:        mgcfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in icscfIP:       icscfIP.append(xdr['dip'][-1])
                    invite_list[line_no + 1]['interface'] = 'Mw3'
                    invite_list[line_no + 1]['dir'] = '1'
                    invite_list[line_no + 1]['msgType'] = 1063
                    invite_list[line_no + 1]['mode'] = 'Complete'
                    if invite_list[line_no + 1]['sip'][-1] not in icscfIP:       icscfIP.append(invite_list[line_no + 1]['sip'][-1])
                    if invite_list[line_no + 1]['dip'][-1] not in scscfIP:       scscfIP.append(invite_list[line_no + 1]['dip'][-1])
                    invite_list[line_no + 2]['interface'] = 'ISC'
                    invite_list[line_no + 2]['dir'] = '0'
                    invite_list[line_no + 2]['msgType'] = 1021
                    invite_list[line_no + 2]['mode'] = 'Complete'
                    if invite_list[line_no + 2]['sip'][-1] not in scscfIP:       scscfIP.append(invite_list[line_no + 2]['sip'][-1])
                    if invite_list[line_no + 2]['dip'][-1] not in asIP:          asIP.append(invite_list[line_no + 2]['dip'][-1])
                elif(line_no + 3 < len(invite_list) and a0 != "" and g0 != None and c0 == "" and sip_1 == dip_2 and l_1 > l_2 and l_2 < l_3 and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'Mg2'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1065
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in mgcfIP:        mgcfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
                    invite_list[line_no + 1]['interface'] = 'ISC'
                    invite_list[line_no + 1]['dir'] = '0'
                    invite_list[line_no + 1]['msgType'] = 1021
                    invite_list[line_no + 1]['mode'] = 'Complete'
                    if invite_list[line_no + 1]['sip'][-1] not in scscfIP:       scscfIP.append(invite_list[line_no + 1]['sip'][-1])
                    if invite_list[line_no + 1]['dip'][-1] not in asIP:          asIP.append(invite_list[line_no + 1]['dip'][-1])
        else:
            if(xdr['mode'] != 'Complete' and line_no + 2 < len(invite_list)):
                m1 =  tag_as(invite_list[line_no + 1].get('Routes',[""])[0])
                m2 =  tag_as(invite_list[line_no + 2].get('Routes',[""])[0])
                s1 = re.search('scscf',invite_list[line_no + 1].get('Routes',[""])[0])
                g0 = re.search('GEN-ACCESS',xdr.get('P_Access_Network_Info',""))
                o0 = re.search('orig-ioi',xdr.get('P_Charging_Vector',""))
                c0 = xdr.get('P_Charging_Vector',"")
                a0 = xdr.get('P_Asserted_Identity',"")
                if(a0 != "" and g0 != None and c0 == "" and s1 != None and m2 !="" and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'Mg1'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1023
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in mgcfIP:        mgcfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in icscfIP:       icscfIP.append(xdr['dip'][-1])
                    invite_list[line_no + 1]['interface'] = 'Mw3'
                    invite_list[line_no + 1]['dir'] = '1'
                    invite_list[line_no + 1]['msgType'] = 1063
                    invite_list[line_no + 1]['mode'] = 'Complete'
                    if invite_list[line_no + 1]['sip'][-1] not in icscfIP:       icscfIP.append(invite_list[line_no + 1]['sip'][-1])
                    if invite_list[line_no + 1]['dip'][-1] not in scscfIP:       scscfIP.append(invite_list[line_no + 1]['dip'][-1])
                    invite_list[line_no + 2]['interface'] = 'ISC'
                    invite_list[line_no + 2]['dir'] = '0'
                    invite_list[line_no + 2]['msgType'] = 1021
                    invite_list[line_no + 2]['keyword4'] = m2
                    invite_list[line_no + 2]['mode'] = 'Complete'
                    if invite_list[line_no + 2]['sip'][-1] not in scscfIP:       scscfIP.append(invite_list[line_no + 2]['sip'][-1])
                    if invite_list[line_no + 2]['dip'][-1] not in asIP:          asIP.append(invite_list[line_no + 2]['dip'][-1])
                elif(line_no + 1 < len(invite_list) and a0 != "" and g0 != None and c0 == "" and s1 == None and m1 !="" and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'Mg2'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1065
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in mgcfIP:        mgcfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
                    invite_list[line_no + 1]['interface'] = 'ISC'
                    invite_list[line_no + 1]['dir'] = '0'
                    invite_list[line_no + 1]['msgType'] = 1021
                    invite_list[line_no + 1]['keyword4'] = m2
                    invite_list[line_no + 1]['mode'] = 'Complete'
                    if invite_list[line_no + 1]['sip'][-1] not in scscfIP:       scscfIP.append(invite_list[line_no + 1]['sip'][-1])
                    if invite_list[line_no + 1]['dip'][-1] not in asIP:          asIP.append(invite_list[line_no + 1]['dip'][-1])
                elif(o0 and s1 and g0 and c0 and a0):
                    xdr['interface'] = 'Mg1'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1023
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in mgcfIP:        mgcfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in icscfIP:       icscfIP.append(xdr['dip'][-1])
                    invite_list[line_no + 1]['interface'] = 'Mw3'
                    invite_list[line_no + 1]['dir'] = '1'
                    invite_list[line_no + 1]['msgType'] = 1063
                    invite_list[line_no + 1]['mode'] = 'Complete'
                    if invite_list[line_no + 1]['sip'][-1] not in icscfIP:       icscfIP.append(invite_list[line_no + 1]['sip'][-1])
                    if invite_list[line_no + 1]['dip'][-1] not in scscfIP:       scscfIP.append(invite_list[line_no + 1]['dip'][-1])

def find_ICSCF(invite_list):
    # find 1001 LIR
    # bug Mw2
    LIR_list = []
    for line_no, line in enumerate(status.file_mode_xdr):
        f = line.strip().split("|")
        if(f[14] == "1001"):
            unix_time = int(datetime.datetime.timestamp(datetime.datetime.strptime(f[1].split(".")[0], r"%Y-%m-%d %H:%M:%S")))
            LIR_list.append(unix_time *1000000000+int(f[1].split(".")[1]))
    # 增加一个功能 icscf LIR icscf
    for line_no, xdr in enumerate(invite_list):
        if(xdr['mode'] != 'Complete' and xdr.get('Routes',['']) == ['']):
            found_LIR = False
            if(line_no + 1 < len(invite_list)):
                ts1 = xdr['ts'][0]*1000000000 + xdr['ts'][1]
                ts2 = invite_list[line_no + 1]['ts'][0]*1000000000 + invite_list[line_no + 1]['ts'][1]
                for ts in LIR_list:
                    if(ts2 - ts1 < 4000000000 and ts1 < ts and ts < ts2):
                        found_LIR = True
                        break
            xdr['mode'] = 'ICSCF candidate'
            m1 = re.search(r'mgcf',xdr['CallID'],flags=re.I)
            m2 = re.search(r'mrfc',xdr['Receiver'],flags=re.I)
            orig_ioi = re.search('orig-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
            term_ioi = re.search('term-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
            if(found_LIR and xdr['Max_Forwards'] != 70 and xdr.get('esp',False) == False and xdr.get('gtp',False) == False and len(xdr['sip'][-1]) == 4):
                xdr['interface'] = 'Mw3'
                xdr['msgType'] = 1063
                xdr['dir'] = '0'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in scscfIP:      scscfIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in icscfIP:      icscfIP.append(xdr['dip'][-1])
                status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                if(line_no + 2 < len(invite_list) and invite_list[line_no + 1]['CallID'] == xdr['CallID'] and invite_list[line_no + 2]['CallID'] == invite_list[line_no + 1]['CallID']):
                    s1 = re.search('scscf', invite_list[line_no + 1].get('Routes',[""])[0],flags=re.I)
                    a2 = tag_as(invite_list[line_no + 2].get('Routes',[""])[0])
                    if(s1 != None and a2 != ''):
                        invite_list[line_no + 1]['interface'] = 'Mw3'
                        invite_list[line_no + 1]['msgType'] = 1063
                        invite_list[line_no + 1]['dir'] = '1'
                        invite_list[line_no + 1]['mode'] = 'Complete'
                        if invite_list[line_no + 1]['sip'][-1] not in icscfIP:      icscfIP.append(invite_list[line_no + 1]['sip'][-1])
                        if invite_list[line_no + 1]['dip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 1]['dip'][-1])
                        invite_list[line_no + 2]['interface'] = 'ISC'
                        invite_list[line_no + 2]['msgType'] = 1021
                        invite_list[line_no + 2]['dir'] = '0'
                        invite_list[line_no + 2]['keyword4'] = a2
                        invite_list[line_no + 2]['mode'] = 'Complete'
                        if invite_list[line_no + 2]['sip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 2]['sip'][-1])
                        if invite_list[line_no + 2]['dip'][-1] not in asIP:         asIP.append(invite_list[line_no + 2]['dip'][-1])
            elif(m2 and len(xdr['sip'][-1]) == 4):
                xdr['interface'] = 'Mr'
                xdr['msgType'] = 1071
                xdr['dir'] = '0'
                xdr['keyword4'] = ''
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] in scscfIP:
                    xdr['keyword4'] = 'SCSCF'
                elif xdr['sip'][-1] in asIP:
                    AS_dict = dict([(x['dip'][-1],xdr['keyword4']) for x in status.sipXDR if x['interface'] == 'ISC' and x['dir'] == '0' and x['keyword4'] != ''])
                    xdr['keyword4'] = AS_dict.get(xdr['dip'][-1],"AS")
                if xdr['dip'][-1] not in mrfcIP:    mrfcIP.append(xdr['dip'][-1])
            elif(xdr.get('gtp', False)):
                if(xdr.get('P_Preferred_Identity','') != ''):
                    xdr['interface'] = 'GmOverGTP'
                    xdr['msgType'] = 1053
                    xdr['dir'] = '0'
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
                elif(xdr.get('P_Asserted_Identity','') != ''):
                    xdr['interface'] = 'GmOverGTP'
                    xdr['msgType'] = 1053
                    xdr['dir'] = '1'
                    xdr['mode'] = 'Complete'
                    if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
                    if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
                else:
                   print('{}: {}'.format(xdr['id'],"has not GTP and has not either P_Preferred_Identity or P_Asserted_Identity"))
            elif(xdr.get('esp', False)):
                if(xdr.get('P_Preferred_Identity','') != '' and len(xdr['sip'][-1]) > 4):
                    xdr['interface'] = 'Gm'
                    xdr['msgType'] = 1015
                    xdr['dir'] = '0'
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
                elif(xdr.get('P_Asserted_Identity','') != '' and len(xdr['sip'][-1]) > 4):
                    xdr['interface'] = 'Gm'
                    xdr['msgType'] = 1015
                    xdr['dir'] = '1'
                    xdr['mode'] = 'Complete'
                    if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
                    if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
            elif(xdr.get('P_Charging_Vector','') == ''):
                if(xdr.get('P_Preferred_Identity','') != '' and len(xdr['sip'][-1]) > 4):
                    xdr['interface'] = 'Gm'
                    xdr['msgType'] = 1015
                    xdr['dir'] = '0'
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
                    status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
                # elif(xdr.get('P_Asserted_Identity','') != ''):
                #     xdr['interface'] = 'Gm'
                #     xdr['msgType'] = 1015
                #     xdr['dir'] = '1'
                #     xdr['mode'] = 'Complete'
                #     if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
                #     if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
                #     status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
                    if(line_no >= 2 and len(xdr['sip'][-1]) == 4):
                        orig_ioi_1 = re.search('orig-ioi=',"" if invite_list[line_no - 1]['P_Charging_Vector'] == '' else invite_list[line_no - 1]['P_Charging_Vector'],flags=re.I)
                        orig_ioi_2 = re.search('orig-ioi=',"" if invite_list[line_no - 2]['P_Charging_Vector'] == '' else invite_list[line_no - 2]['P_Charging_Vector'],flags=re.I)
                        if(orig_ioi_1 == None and orig_ioi_2 != None):
                            invite_list[line_no - 1]['interface'] = 'Mw2'
                            invite_list[line_no - 1]['msgType'] = 1061
                            invite_list[line_no - 1]['dir'] = '1'
                            invite_list[line_no - 1]['mode'] = 'Complete'
                            if invite_list[line_no - 1]['sip'][-1] not in scscfIP:         scscfIP.append(invite_list[line_no - 1]['sip'][-1])
                            if invite_list[line_no - 1]['dip'][-1] not in sbcCoreIP:       sbcCoreIP.append(invite_list[line_no - 1]['dip'][-1])
                            invite_list[line_no - 2]['interface'] = 'ISC'
                            invite_list[line_no - 2]['msgType'] = 1021
                            invite_list[line_no - 2]['dir'] = '1'
                            invite_list[line_no - 2]['mode'] = 'Complete'
                            invite_list[line_no - 2]['keyword4'] = tag_as(invite_list[line_no - 2].get('Routes',[""])[0])
                            if invite_list[line_no - 2]['sip'][-1] not in asIP:            asIP.append(invite_list[line_no - 2]['sip'][-1])
                            if invite_list[line_no - 2]['dip'][-1] not in scscfIP:         scscfIP.append(invite_list[line_no - 2]['dip'][-1])
                else:
                    print('{}: {}'.format(xdr['id'],"has not ESP and has not either P_Preferred_Identity or P_Charging_Vector"))
            else:
                orig_ioi = re.search('orig-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
                term_ioi = re.search('term-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
                if(orig_ioi != None and term_ioi == None):
                    if(line_no + 1 < len(invite_list) and invite_list[line_no + 1]['Route'] != ''):
                        if(invite_list[line_no + 1]['CallID'] == xdr['CallID']  and len(xdr['sip'][-1]) == 4):
                            m = re.search(r'FFFFFFFF',invite_list[line_no + 1].get('Routes',[""])[0],flags=re.I)
                            if m:
                                if line_no + 2 < len(invite_list): 
                                    orig_ioi_1 = re.search('orig-ioi=',"" if invite_list[line_no + 1]['P_Charging_Vector'] == '' else invite_list[line_no + 1]['P_Charging_Vector'],flags=re.I)
                                    term_ioi_1 = re.search('term-ioi=',"" if invite_list[line_no + 1]['P_Charging_Vector'] == '' else invite_list[line_no + 1]['P_Charging_Vector'],flags=re.I)
                                    orig_ioi_2 = re.search('orig-ioi=',"" if invite_list[line_no + 2]['P_Charging_Vector'] == '' else invite_list[line_no + 2]['P_Charging_Vector'],flags=re.I)
                                    term_ioi_2 = re.search('term-ioi=',"" if invite_list[line_no + 2]['P_Charging_Vector'] == '' else invite_list[line_no + 2]['P_Charging_Vector'],flags=re.I)
                                    if(orig_ioi_1 != None and term_ioi_1 != None and len(xdr['sip'][-1]) == 4):   # icscf collocated with scscf
                                        xdr['interface'] = 'Mw3'
                                        xdr['msgType'] = 1063
                                        xdr['dir'] = '0'
                                        xdr['mode'] = 'Complete'
                                        if xdr['sip'][-1] not in scscfIP:      scscfIP.append(xdr['sip'][-1])
                                        if xdr['dip'][-1] not in icscfIP:      icscfIP.append(xdr['dip'][-1])
                                        status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                                        invite_list[line_no + 1]['interface'] = 'ISC'
                                        invite_list[line_no + 1]['msgType'] = 1021
                                        invite_list[line_no + 1]['dir'] = '0'
                                        invite_list[line_no + 1]['mode'] = 'Complete'
                                        if invite_list[line_no + 1]['sip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 1]['sip'][-1])
                                        if invite_list[line_no + 1]['dip'][-1] not in asIP:         asIP.append(invite_list[line_no + 1]['dip'][-1])
                                    elif((orig_ioi_2 != None and term_ioi_2 != None) and len(xdr['sip'][-1]) == 4):
                                        xdr['interface'] = 'Mw3'
                                        xdr['msgType'] = 1063
                                        xdr['dir'] = '0'
                                        xdr['mode'] = 'Complete'
                                        if xdr['sip'][-1] not in scscfIP:      scscfIP.append(xdr['sip'][-1])
                                        if xdr['dip'][-1] not in icscfIP:      icscfIP.append(xdr['dip'][-1])
                                        status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                                        invite_list[line_no + 1]['interface'] = 'Mw3'
                                        invite_list[line_no + 1]['msgType'] = 1063
                                        invite_list[line_no + 1]['dir'] = '1'
                                        invite_list[line_no + 1]['mode'] = 'Complete'
                                        if invite_list[line_no + 1]['sip'][-1] not in icscfIP:      icscfIP.append(invite_list[line_no + 1]['sip'][-1])
                                        if invite_list[line_no + 1]['dip'][-1] not in scscfIP:         scscfIP.append(invite_list[line_no + 1]['dip'][-1])
                                        invite_list[line_no + 2]['interface'] = 'ISC'
                                        invite_list[line_no + 2]['msgType'] = 1021
                                        invite_list[line_no + 2]['dir'] = '0'
                                        invite_list[line_no + 2]['mode'] = 'Complete'
                                        invite_list[line_no + 2]['keyword4'] = tag_as(invite_list[line_no + 2].get('Routes',[""])[0])
                                        if invite_list[line_no + 2]['sip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 2]['sip'][-1])
                                        if invite_list[line_no + 2]['dip'][-1] not in asIP:         asIP.append(invite_list[line_no + 2]['dip'][-1])
                            else:
                                if(line_no >= 0 and line_no < len(invite_list) - 2  and len(xdr['sip'][-1]) == 4):
                                    m = tag_as(invite_list[line_no + 2].get('Routes',[""])[0])
                                    next_hop_type = re.search('scscf', invite_list[line_no + 1]['Route'],flags=re.I)
                                    if m != ''  and next_hop_type != None:
                                        if(len(xdr['branch']) < len(invite_list[line_no + 1]['branch']) and len(invite_list[line_no + 1]['branch']) < len(invite_list[line_no + 2]['branch']) and re.search(xdr['branch'].replace('*','#'), invite_list[line_no + 1]['branch'].replace('*','#')) != None and re.search(invite_list[line_no + 1]['branch'].replace('*','#'), invite_list[line_no + 2]['branch'].replace('*','#')) != None):
                                            if(m1 and orig_ioi !=  None and term_ioi == None):
                                                xdr['interface'] = 'Mg1'
                                                xdr['msgType'] = 1023
                                                xdr['dir'] = '0'
                                                xdr['mode'] = 'Complete'
                                                if xdr['sip'][-1] not in mgcfIP:       mgcfIP.append(xdr['sip'][-1])
                                                if xdr['dip'][-1] not in icscfIP:      icscfIP.append(xdr['dip'][-1])
                                                status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                                            else:
                                                xdr['interface'] = 'Mw3'
                                                xdr['msgType'] = 1063
                                                xdr['dir'] = '0'
                                                xdr['mode'] = 'Complete'
                                                if xdr['sip'][-1] not in scscfIP:       scscfIP.append(xdr['sip'][-1])
                                                if xdr['dip'][-1] not in icscfIP:       icscfIP.append(xdr['dip'][-1])
                                                status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                                            invite_list[line_no + 1]['interface'] = 'Mw3'
                                            invite_list[line_no + 1]['msgType'] = 1063
                                            invite_list[line_no + 1]['dir'] = '1'
                                            invite_list[line_no + 1]['mode'] = 'Complete'

                                            if invite_list[line_no + 1]['sip'][-1] not in icscfIP:      icscfIP.append(invite_list[line_no + 1]['sip'][-1])
                                            if invite_list[line_no + 1]['dip'][-1] not in scscfIP:         scscfIP.append(invite_list[line_no + 1]['dip'][-1])
                                            invite_list[line_no + 2]['interface'] = 'ISC'
                                            invite_list[line_no + 2]['msgType'] = 1021
                                            invite_list[line_no + 2]['dir'] = '0'
                                            invite_list[line_no + 2]['mode'] = 'Complete'
                                            invite_list[line_no + 2]['keyword4'] = tag_as(invite_list[line_no + 2].get('Routes',[""])[0])
                                            if invite_list[line_no + 2]['sip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 2]['sip'][-1])
                                            if invite_list[line_no + 2]['dip'][-1] not in asIP:         asIP.append(invite_list[line_no + 2]['dip'][-1])
                                            invite_list[line_no + 2]['keyword4'] = tag_as(invite_list[line_no + 2].get('Routes',[""])[0])
                                elif(line_no >= 1 and line_no + 2 < len(invite_list)):
                                    m = tag_as(invite_list[line_no + 2].get('Routes',[""])[0])
                                    next_hop_type = re.search('scscf', invite_list[line_no + 1]['Route'],flags=re.I)
                                    if m != '':
                                        if(len(invite_list[line_no - 1]['branch']) < len(xdr['branch']) and len(xdr['branch']) < len(invite_list[line_no + 1]['branch']) and re.search(invite_list[line_no - 1]['branch'].replace('*','#'), xdr['branch'].replace('*','#')) != None and re.search(xdr['branch'].replace('*','#'), invite_list[line_no + 1]['branch'].replace('*','#')) != None and len(xdr['sip'][-1]) == 4):
                                            # invite消息不可能有Mw4
                                            # xdr['interface'] = 'Mw4'
                                            # xdr['msgType'] = 1069
                                            # xdr['dir'] = '0'
                                            # xdr['mode'] = 'Complete'
                                            # if xdr['sip'][-1] not in scscfIP:       scscfIP.append(xdr['sip'][-1])
                                            # if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
                                            # status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                                            invite_list[line_no + 1]['interface'] = 'ISC'
                                            invite_list[line_no + 1]['msgType'] = 1021
                                            invite_list[line_no + 1]['dir'] = '0'
                                            invite_list[line_no + 1]['mode'] = 'Complete'
                                            invite_list[line_no + 1]['keyword4'] = tag_as(invite_list[line_no + 1].get('Routes',[""])[0])
                                            if invite_list[line_no + 1]['sip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 1]['sip'][-1])
                                            if invite_list[line_no + 1]['dip'][-1] not in asIP:         asIP.append(invite_list[line_no + 1]['dip'][-1])
                                    elif(next_hop_type != None and len(xdr['sip'][-1]) == 4):
                                        xdr['interface'] = 'Mw3'
                                        xdr['msgType'] = 1063
                                        xdr['dir'] = '0'
                                        xdr['mode'] = 'Complete'
                                        if xdr['sip'][-1] not in scscfIP:      scscfIP.append(xdr['sip'][-1])
                                        if xdr['dip'][-1] not in icscfIP:      icscfIP.append(xdr['dip'][-1])
                                        status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                                        invite_list[line_no + 1]['interface'] = 'Mw3'
                                        invite_list[line_no + 1]['msgType'] = 1063
                                        invite_list[line_no + 1]['dir'] = '1'
                                        invite_list[line_no + 1]['mode'] = 'Complete'
                                        if invite_list[line_no + 1]['sip'][-1] not in icscfIP:      icscfIP.append(invite_list[line_no + 1]['sip'][-1])
                                        if invite_list[line_no + 1]['dip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 1]['dip'][-1])
                        else:
                            xdr['mode'] = 'No Routes but next hop is not the same CallID'
                    else:
                        xdr['mode'] = 'No Routes but next hop has not Routes'
                else:
                    pass
        elif(xdr.get('Routes',['']) != ['']):
            m = re.search(r'scscf',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                if(line_no + 1 < len(invite_list) and invite_list[line_no + 1].get('Routes',[""])[0] != '' and line_no > 0 and invite_list[line_no + 1]['CallID'] == xdr['CallID'] and invite_list[line_no - 1]['CallID'] == xdr['CallID'] and invite_list[line_no - 1]['mode'] != 'Complete'):
                    m = tag_as(invite_list[line_no + 1].get('Routes',[""])[0])
                    if m != '':
                        if(len(invite_list[line_no - 1]['branch']) < len(xdr['branch']) and len(xdr['branch']) < len(invite_list[line_no + 1]['branch']) and re.search(invite_list[line_no - 1]['branch'].replace('*','#'), xdr['branch'].replace('*','#')) != None and re.search(xdr['branch'].replace('*','#'), invite_list[line_no + 1]['branch'].replace('*','#')) != None and len(xdr['sip'][-1]) == 4):
                            r = re.search(r'icscf',invite_list[line_no - 1].get('Routes',[""])[0],flags=re.I)
                            if r:
                                xdr['interface'] = 'Mw3'
                                xdr['msgType'] = 1069
                                xdr['dir'] = '1'
                                xdr['mode'] = 'Complete'
                                if xdr['sip'][-1] not in icscfIP:       icscfIP.append(xdr['sip'][-1])
                                if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
                                invite_list[line_no - 1]['interface'] = 'Mw3'
                                invite_list[line_no - 1]['msgType'] = 1069
                                invite_list[line_no - 1]['dir'] = '0'
                                invite_list[line_no - 1]['mode'] = 'Complete'
                                if invite_list[line_no - 1]['sip'][-1] not in scscfIP:       scscfIP.append(xdr['sip'][-1])
                                if invite_list[line_no - 1]['dip'][-1] not in icscfIP:       icscfIP.append(xdr['dip'][-1])
                                status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                            # else:
                            #     xdr['interface'] = 'Mw4'
                            #     xdr['msgType'] = 1069
                            #     xdr['dir'] = '0'
                            #     xdr['mode'] = 'Complete'
                            #     if xdr['sip'][-1] not in scscfIP:       scscfIP.append(xdr['sip'][-1])
                            #     if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
                            invite_list[line_no + 1]['interface'] = 'ISC'
                            invite_list[line_no + 1]['msgType'] = 1021
                            invite_list[line_no + 1]['dir'] = '0'
                            invite_list[line_no + 1]['mode'] = 'Complete'
                            invite_list[line_no + 1]['keyword4'] = tag_as(invite_list[line_no + 1].get('Routes',[""])[0])
                            if invite_list[line_no + 1]['sip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 1]['sip'][-1])
                            if invite_list[line_no + 1]['dip'][-1] not in asIP:         asIP.append(invite_list[line_no + 1]['dip'][-1])
                elif(line_no > 1 and invite_list[line_no - 1].get('Routes',[""])[0] != '' and invite_list[line_no - 1]['CallID'] == xdr['CallID'] and invite_list[line_no - 1]['mode'] != 'Complete'  and len(xdr['sip'][-1]) == 4):
                    r = re.search(r'icscf',invite_list[line_no - 1].get('Routes',[""])[0],flags=re.I)
                    if r:
                        xdr['interface'] = 'Mw3'
                        xdr['msgType'] = 1069
                        xdr['dir'] = '1'
                        xdr['mode'] = 'Complete'
                        if xdr['sip'][-1] not in icscfIP:       icscfIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
                        invite_list[line_no - 1]['interface'] = 'Mw3'
                        invite_list[line_no - 1]['msgType'] = 1069
                        invite_list[line_no - 1]['dir'] = '0'
                        invite_list[line_no - 1]['mode'] = 'Complete'
                        if invite_list[line_no - 1]['sip'][-1] not in scscfIP:       scscfIP.append(xdr['sip'][-1])
                        if invite_list[line_no - 1]['dip'][-1] not in icscfIP:       icscfIP.append(xdr['dip'][-1])
                        status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
            elif(line_no + 1 < len(invite_list) and invite_list[line_no + 1]['CallID'] == xdr['CallID']  and len(xdr['sip'][-1]) == 4):
                orig_ioi = re.search('orig-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
                term_ioi = re.search('term-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
                if(orig_ioi != None and term_ioi == None):
                    m = re.search(r'FFFFFFFF',invite_list[line_no + 1].get('Routes',[""])[0],flags=re.I)
                    if m:
                        if line_no + 2 < len(invite_list): 
                            orig_ioi_1 = re.search('orig-ioi=',"" if invite_list[line_no + 1]['P_Charging_Vector'] == '' else invite_list[line_no + 1]['P_Charging_Vector'],flags=re.I)
                            term_ioi_1 = re.search('term-ioi=',"" if invite_list[line_no + 1]['P_Charging_Vector'] == '' else invite_list[line_no + 1]['P_Charging_Vector'],flags=re.I)
                            orig_ioi_2 = re.search('orig-ioi=',"" if invite_list[line_no + 2]['P_Charging_Vector'] == '' else invite_list[line_no + 2]['P_Charging_Vector'],flags=re.I)
                            term_ioi_2 = re.search('term-ioi=',"" if invite_list[line_no + 2]['P_Charging_Vector'] == '' else invite_list[line_no + 2]['P_Charging_Vector'],flags=re.I)
                            if(orig_ioi_1 != None and term_ioi_1 != None):   # icscf collocated with scscf
                                # xdr['interface'] = 'Mw3'
                                # xdr['msgType'] = 1063
                                # xdr['dir'] = '0'
                                # xdr['mode'] = 'Complete'
                                # if xdr['sip'][-1] not in scscfIP:      iscscfIP.append(xdr['sip'][-1])
                                # if xdr['dip'][-1] not in icscfIP:      icscfIP.append(xdr['dip'][-1])
                                status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                                invite_list[line_no + 1]['interface'] = 'ISC'
                                invite_list[line_no + 1]['msgType'] = 1021
                                invite_list[line_no + 1]['dir'] = '0'
                                invite_list[line_no + 1]['mode'] = 'Complete'
                                invite_list[line_no + 1]['keyword4'] = tag_as(invite_list[line_no + 1].get('Routes',[""])[0])
                                if invite_list[line_no + 1]['sip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 1]['sip'][-1])
                                if invite_list[line_no + 1]['dip'][-1] not in asIP:         asIP.append(invite_list[line_no + 1]['dip'][-1])
                            elif((orig_ioi_2 != None and term_ioi_2 != None)):
                                xdr['interface'] = 'Mw3'
                                xdr['msgType'] = 1063
                                xdr['dir'] = '0'
                                xdr['mode'] = 'Complete'
                                if xdr['sip'][-1] not in scscfIP:      scscfIP.append(xdr['sip'][-1])
                                if xdr['dip'][-1] not in icscfIP:      icscfIP.append(xdr['dip'][-1])
                                status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                                invite_list[line_no + 1]['interface'] = 'Mw3'
                                invite_list[line_no + 1]['msgType'] = 1063
                                invite_list[line_no + 1]['dir'] = '1'
                                invite_list[line_no + 1]['mode'] = 'Complete'
                                if invite_list[line_no + 1]['sip'][-1] not in icscfIP:         icscfIP.append(invite_list[line_no + 1]['sip'][-1])
                                if invite_list[line_no + 1]['dip'][-1] not in scscfIP:         scscfIP.append(invite_list[line_no + 1]['dip'][-1])
                                invite_list[line_no + 2]['interface'] = 'ISC'
                                invite_list[line_no + 2]['msgType'] = 1021
                                invite_list[line_no + 2]['dir'] = '0'
                                invite_list[line_no + 2]['mode'] = 'Complete'
                                if invite_list[line_no + 2]['sip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 2]['sip'][-1])
                                if invite_list[line_no + 2]['dip'][-1] not in asIP:         asIP.append(invite_list[line_no + 2]['dip'][-1])
                    else:
                        if line_no + 2 < len(invite_list): 
                            orig_ioi = re.search('orig-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
                            term_ioi = re.search('term-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
                            orig_ioi_1 = re.search('orig-ioi=',"" if invite_list[line_no + 1]['P_Charging_Vector'] == '' else invite_list[line_no + 1]['P_Charging_Vector'],flags=re.I)
                            term_ioi_1 = re.search('term-ioi=',"" if invite_list[line_no + 1]['P_Charging_Vector'] == '' else invite_list[line_no + 1]['P_Charging_Vector'],flags=re.I)
                            orig_ioi_2 = re.search('orig-ioi=',"" if invite_list[line_no + 2]['P_Charging_Vector'] == '' else invite_list[line_no + 2]['P_Charging_Vector'],flags=re.I)
                            term_ioi_2 = re.search('term-ioi=',"" if invite_list[line_no + 2]['P_Charging_Vector'] == '' else invite_list[line_no + 2]['P_Charging_Vector'],flags=re.I)
                            next_hop_type = re.search('scscf', invite_list[line_no + 1]['Route'],flags=re.I)
                            branch = xdr['branch'].split('|')
                            branch1 = invite_list[line_no + 1]['branch'].split('|')
                            branch2 = invite_list[line_no + 2]['branch'].split('|')
                            if(len(branch) == 1 and len(branch1) == 2 and len(branch2) == 3 and branch[0] == branch1[1] and branch1[0] == branch2[1] and branch1[1] == branch2[2]):
                                if(next_hop_type):
                                    if(orig_ioi != None and term_ioi == None and orig_ioi_1 != None and term_ioi_1 == None and orig_ioi_2 != None and term_ioi_2 != None):
                                        xdr['interface'] = 'Mg1'
                                        xdr['msgType'] = 1023
                                        xdr['dir'] = '0'
                                        xdr['mode'] = 'Complete'
                                        if xdr['sip'][-1] not in mgcfIP:       mgcfIP.append(xdr['sip'][-1])
                                        if xdr['dip'][-1] not in icscfIP:      icscfIP.append(xdr['dip'][-1])
                                        status.sipStatus.setdefault('Mw3',[]).append(xdr['id'])
                                        invite_list[line_no + 1]['interface'] = 'Mw3'
                                        invite_list[line_no + 1]['msgType'] = 1063
                                        invite_list[line_no + 1]['dir'] = '1'
                                        invite_list[line_no + 1]['mode'] = 'Complete'
                                        if invite_list[line_no + 1]['sip'][-1] not in icscfIP:      icscfIP.append(invite_list[line_no + 1]['sip'][-1])
                                        if invite_list[line_no + 1]['dip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 1]['dip'][-1])
                                        # invite_list[line_no + 2]['interfacide'] = 'ISC'
                                        # invite_list[line_no + 2]['msgType'] = 1021
                                        # invite_list[line_no + 2]['dir'] = '0'
                                        # invite_list[line_no + 2]['mode'] = 'Complete'
                                        # invite_list[line_no + 2]['keyword4'] = tag_as(invite_list[line_no + 2].get('Routes',[""])[0])
                                        # if invite_list[line_no + 2]['sip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 2]['sip'][-1])
                                        # if invite_list[line_no + 2]['dip'][-1] not in asIP:         asIP.append(invite_list[line_no + 2]['dip'][-1])

def mo_leg(invite_list):
    Mw3_list = status.sipStatus.get('Mw3',None)
    Mw3_no = len(invite_list)
    if(Mw3_list != None):
        Mw3_no = [x[0] for x in enumerate(invite_list,1) if x[1]['id'] == Mw3_list[0]][0]

    Is_Routes_masked = False
    for line_no, xdr in enumerate(invite_list[:Mw3_no]):
        m = re.search(r'FFFFFFFFFF|\*\*\*\*\*\*\*\*\*\*',xdr.get('Routes',[""])[0],flags=re.I)
        if m:
            Is_Routes_masked = True
        if(xdr.get('gtp', False) and xdr['mode'] != 'Complete'):
            if(xdr.get('P_Preferred_Identity','') != ''):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
                xdr['dir'] = '0'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
                status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
            else:
                print('{}: {}'.format(xdr['id'],"has GTP but has not P_Preferred_Identity")) 
        elif(xdr['P_Asserted_Identity'] != '' and xdr['Routes'] == [''] and xdr['P_Charging_Vector'] == '' and xdr.get('IPv6',False) == True and xdr['mode'] != 'Complete'):
            if(xdr.get('gtp', False)):                                                  # with GTP, the interface is GmOverGTP
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
                xdr['dir'] = '1'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
                status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
            else:                                                                       # with only esp or without esp, interface is Gm
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
                xdr['dir'] = '1'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
                status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
        elif(xdr.get('esp', False) and xdr['mode'] != 'Complete'):
            if(xdr.get('P_Preferred_Identity','') != ''):
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
                xdr['dir'] = '0'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
                status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
            else:
                print('{}: {}'.format(xdr['id'],"has ESP but has not P_Preferred_Identity"))
        elif(xdr.get('P_Preferred_Identity','') != '' and xdr['mode'] != 'Complete'):
            xdr['interface'] = 'Gm'
            xdr['msgType'] = 1015
            xdr['dir'] = '0'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
            status.sipStatus.setdefault('Gm',[]).append(xdr['id'])
            if(line_no + 1 < Mw3_no and invite_list[line_no+1].get('Max_Forwards',0) == 69):
                orig_ioi = re.search('orig-ioi=',"" if invite_list[line_no+1]['P_Charging_Vector'] == '' else invite_list[line_no+1]['P_Charging_Vector'],flags=re.I)
                term_ioi = re.search('term-ioi=',"" if invite_list[line_no+1]['P_Charging_Vector'] == '' else invite_list[line_no+1]['P_Charging_Vector'],flags=re.I)
                if(orig_ioi == None and term_ioi == None):
                    invite_list[line_no+1]['interface'] = 'Mw2'
                    invite_list[line_no+1]['msgType'] = 1061
                    invite_list[line_no+1]['dir'] = '0'
                    invite_list[line_no+1]['mode'] = 'Complete'
                    if invite_list[line_no+1]['sip'][-1] not in sbcCoreIP:       sbcCoreIP.append(invite_list[line_no+1]['sip'][-1])
                    if invite_list[line_no+1]['dip'][-1] not in scscfIP:         scscfIP.append(invite_list[line_no+1]['dip'][-1])
        elif(xdr['mode'] != 'Complete'):
            is_scscf = re.search('scscf',xdr.get('Routes',[""])[0],flags=re.I)
            if(line_no >=1 and invite_list[line_no-1].get('P_Preferred_Identity','') != '' and is_scscf != None and len(xdr['sip'][-1]) == 4):
                xdr['interface'] = 'Mw2'
                xdr['msgType'] = 1061
                xdr['dir'] = '0'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in sbcCoreIP:     sbcCoreIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
                status.sipStatus.setdefault('Mw2',[]).append(xdr['id'])
            # Mg has not finished
            else:
                xdr['keyword4'] = tag_as(xdr.get('Routes',[""])[0])
                if(xdr['keyword4'] != '' and len(xdr['sip'][-1]) == 4):
                    xdr['interface'] = 'ISC'
                    xdr['msgType'] = 1021
                    xdr['dir'] = '0'
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in scscfIP: scscfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in asIP:    asIP.append(xdr['dip'][-1])
                    if(line_no + 1 < Mw3_no and len(xdr['Routes']) >= 2 and xdr['Routes'][1] == invite_list[line_no+1]['Routes'][0]):
                        invite_list[line_no+1]['interface'] = 'ISC'
                        invite_list[line_no+1]['msgType'] = 1021
                        invite_list[line_no+1]['dir'] = '1'
                        invite_list[line_no+1]['mode'] = 'Complete'
                        invite_list[line_no+1]['keyword4'] = xdr['keyword4']
                        if invite_list[line_no+1]['sip'][-1] not in asIP:       asIP.append(invite_list[line_no+1]['sip'][-1])
                        if invite_list[line_no+1]['dip'][-1] not in scscfIP:    scscfIP.append(invite_list[line_no+1]['dip'][-1])

                # mgcf: SCSCF -->MGCF, 可确定目标网元是MGCF，接口为Mg；源网元可能是SCSCF/ISBG/BGCF，标为SCSCF也没问题
                # Mg1	INVITE		Mg->I	Mgcf <--> ICSCF	(非 ICS，业务域选在 CS 域)
                # Mg2	INVITE		Mg->S	Mgcf <--> SCSCF	(是 ICS,  业务域选在 IMS 域)
                m = re.search(r'mgcf',xdr.get('Routes',[""])[0],flags=re.I)
                if m and len(xdr['sip'][-1]) == 4:
                    xdr['interface'] = 'Mg2'
                    xdr['dir'] = '1'
                    xdr['msgType'] = 1065
                    xdr['mode'] = 'Complete'
                    if xdr['dip'][-1] not in mgcfIP:  mgcfIP.append(xdr['dip'][-1])
                # bgcf: SCSCF --> BGCF，可确定目标网元是BGCF，接口为Mi
                m = re.search(r'bgcf',xdr.get('Routes',[""])[0],flags=re.I)
                if m and len(xdr['sip'][-1]) == 4:
                    xdr['interface'] = 'Mi'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1071
                    xdr['mode'] = 'Complete'
                    if xdr['dip'][-1] not in bgcfIP:  bgcfIP.append(xdr['dip'][-1])
                # isbg: SCSCF --> ISBG，可确定目标网元是 ISBG，接口为Mw
                m = re.search(r'isbg',xdr.get('Routes',[""])[0],flags=re.I)
                if m and len(xdr['sip'][-1]) == 4:
                    xdr['interface'] = 'ISBG'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1067
                    xdr['mode'] = 'Complete'
                    if xdr['dip'][-1] not in isbgIP:  isbgIP.append(xdr['dip'][-1])
                # # scpas: SCSCF --> SCP，可确定目标网元是 SCP，接口为ISC
                m = re.search(r'scpas',xdr.get('Routes',[""])[0],flags=re.I)
                if m and len(xdr['sip'][-1]) == 4:
                    xdr['interface'] = 'ISC'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1021
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in scscfIP:  scscfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in asIP:  asIP.append(xdr['dip'][-1])
                # sbc: XXX -->SBC，可确定目标网元是SBC，接口不确定
                m = re.search(r'sbc',xdr.get('Routes',[""])[0],flags=re.I)
                if m and len(xdr['sip'][-1]) == 4:
                    if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
                # atcf: eMSC -->SBC，可确定目标网元是ATCF即SBC，接口为 I2 (i2)；
                m = re.search(r'atcf.*\.org',xdr.get('Routes',[""])[0],flags=re.I)
                if m and len(xdr['sip'][-1]) == 4:
                    if xdr['sip'][-1] in scscfIP:
                        xdr['interface'] = 'Mw2'
                        xdr['dir'] = '1'
                        if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
                    else:
                        xdr['interface'] = 'I2'
                        xdr['dir'] = '0'
                        xdr['msgType'] = 1051
                        xdr['mode'] = 'Complete'
                        if xdr['sip'][-1] not in eMSCIP:     eMSCIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
                # term: SCSCF --> SBC --> (UE), 可确定目标网元是SBC，源网元是SCSCF，接口为Mw； ---- 这条没验证，只看到一个例子，可以先试着用；
                m = re.search(r'sip:term@',xdr.get('Routes',[""])[0],flags=re.I)
                if m and len(xdr['sip'][-1]) == 4:
                    xdr['interface'] = 'Mw2'
                    xdr['dir'] = '1'
                    xdr['msgType'] = 1061
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in scscfIP:    scscfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
                # scscf: 有两种情况，所以不判断源网元，标记目标网元为SCSCF；
                # [1] (UE) -> SBC -> SCSCF，可确定目标网元是SCSCF，源网元是SBC，接口为 Gm 或 GmOverGTP，可根据有无 GTP 封装来确定；
                # [2]             XXX -> SCSCF，接口不能确定（可能是Mw/ISC 等）；
                # m = re.search(r'scscf',Routes[0],flags=re.I)
                # if m:
                #     xdr['interface'] = 'Mw'
                #     xdr['dir'] = '0'
                #     if xdr['sip'][-1] not in scscfIP:  scscfIP.append(xdr['sip'][-1])
                #     if xdr['dip'][-1] not in scscfIP:  scscfIP.append(xdr['dip'][-1])

                # 各种AS（下面列表提供），有两种情况
                # [1]           SCSCF-> AS，可确定目标网元是SCSCF，源网元是AS，接口标为 ISC（可能是 ISC/Ma）；
                # [2] (MSC)->SBC->AS，并且 SIP.message 存在 "Target-Dialog:"头域，接口为 ATCF-SCCAS；
                if xdr['Target_Dialog']:
                    xdr['interface'] = 'ATCF-SCCAS'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1059
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in eMSCIP:     eMSCIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
    if Is_Routes_masked:
        for line_no, xdr in enumerate(invite_list[:Mw3_no]):
            if(xdr['mode'] == 'Complete' and len(xdr['sip'][-1]) == 4):
                continue
            orig_ioi = re.search('orig-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
            term_ioi = re.search('term-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)

            if(orig_ioi != None and term_ioi != None and len(xdr.get('Routes',[""])[0]) > len(invite_list[line_no - 1].get('Routes',[""])[0]) and xdr['CallID'] == invite_list[line_no - 1]['CallID'] and invite_list[line_no - 1]['mode'] != 'Complete'):
                invite_list[line_no - 1]['interface'] = 'ISC'
                invite_list[line_no - 1]['msgType'] = 1021
                invite_list[line_no - 1]['dir'] = '1'
                invite_list[line_no - 1]['mode'] = 'Complete'
                if invite_list[line_no - 1]['sip'][-1] not in asIP:         asIP.append(invite_list[line_no - 1]['sip'][-1])
                if invite_list[line_no - 1]['dip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no - 1]['dip'][-1])
                xdr['interface'] = 'ISC'
                xdr['msgType'] = 1021
                xdr['dir'] = '0'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in scscfIP:      scscfIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in asIP:         asIP.append(xdr['dip'][-1])
            elif(term_ioi == None and len(xdr.get('Routes',[""])[0]) > len(invite_list[line_no - 1].get('Routes',[""])[0]) and xdr['RequestURI'] != invite_list[line_no - 1]['RequestURI'] and invite_list[line_no - 1]['mode'] != 'Complete'):
                if((line_no + 1 == len(invite_list)) or (line_no + 1 < len(invite_list)) and (invite_list[line_no + 1]['ts'][0]- xdr['ts'][0]> 3)):
                    invite_list[line_no - 1]['interface'] = 'ISC'
                    invite_list[line_no - 1]['msgType'] = 1021
                    invite_list[line_no - 1]['dir'] = '1'
                    invite_list[line_no - 1]['mode'] = 'Complete'
                    if invite_list[line_no - 1]['sip'][-1] not in asIP:         asIP.append(invite_list[line_no - 1]['sip'][-1])
                    if invite_list[line_no - 1]['dip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no - 1]['dip'][-1])
                    xdr['interface'] = 'Mw2'
                    xdr['msgType'] = 1061
                    xdr['dir'] = '1'
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in scscfIP:      scscfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcCoreIP:    sbcCoreIP.append(xdr['dip'][-1])
            elif(line_no + 1< Mw3_no and len(xdr['branch']) < len(invite_list[line_no + 1]['branch']) and re.search(xdr['branch'].replace('*','#'), invite_list[line_no + 1]['branch'].replace('*','#')) != None):
                xdr['interface'] = 'ISC'
                xdr['msgType'] = 1021
                xdr['dir'] = '1'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in asIP:         asIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in scscfIP:      scscfIP.append(xdr['dip'][-1])
                if invite_list[line_no + 1]['mode'] != 'Complete':
                    invite_list[line_no + 1]['interface'] = 'ISC'
                    invite_list[line_no + 1]['msgType'] = 1021
                    invite_list[line_no + 1]['dir'] = '0'
                    invite_list[line_no + 1]['mode'] = 'Complete'
                    if invite_list[line_no + 1]['sip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no + 1]['sip'][-1])
                    if invite_list[line_no + 1]['dip'][-1] not in asIP:         asIP.append(invite_list[line_no + 1]['dip'][-1])

def mt_leg(invite_list):
    Mw3_list = status.sipStatus.get('Mw3',None)
    Mw3_no = 0
    if(Mw3_list != None):
        Mw3_no = [x[0] for x in enumerate(invite_list,1) if x[1]['id'] == Mw3_list[0]][0]
    Is_Routes_masked = False
    for line_no, xdr in enumerate(invite_list):
        if(line_no < Mw3_no or xdr['mode'] == 'Complete'):
            continue
        is_scscf = re.search('scscf',xdr.get('Routes',[""])[0],flags=re.I)
        if(xdr.get('P_Asserted_Identity',False) != "" and xdr['Routes'] == [''] and xdr['P_Charging_Vector'] == '' and xdr.get('Max_Forwards',1) != 70 and xdr.get('Max_Forwards',1) != 0 and xdr.get('IPv6',False) == True):
            if(xdr.get('gtp',False) or xdr.get('esp',False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
            else:
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
            xdr['dir'] = '1'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
        if(xdr.get('P_Asserted_Identity',False) != "" and xdr['Routes'] == [''] and xdr.get('Max_Forwards',1) != 70 and xdr.get('Max_Forwards',1) != 0 and xdr.get('IPv6',False) == True):
            if(xdr.get('gtp',False) or xdr.get('esp',False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
            else:
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
            xdr['dir'] = '1'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
        elif(line_no >=1 and invite_list[line_no-1]['interface'] in ('Gm','GmOverGTP') and invite_list[line_no-1]['dir'] == '0' and is_scscf != None and len(xdr['sip'][-1]) == 4):
            xdr['interface'] = 'Mw2'
            xdr['msgType'] = 1061
            xdr['dir'] = '0'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in sbcCoreIP:     sbcCoreIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
            status.sipStatus.setdefault('Mw2',[]).append(xdr['id'])
        # Mg has not finished
        elif(xdr.get('P_Preferred_Identity',"") != "" and xdr.get('P_Charging_Vector',"") == ""):
            if(xdr.get('gtp',False) or xdr.get('esp',False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
            else:
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
            xdr['dir'] = '1'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
        else:
            m = re.search(r'FFFFFFFFFF|\*\*\*\*\*\*\*\*\*\*',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                Is_Routes_masked = True

            xdr['keyword4'] = tag_as(xdr.get('Routes',[""])[0])
            if(xdr['keyword4'] != '' and len(xdr['sip'][-1]) == 4):
                xdr['interface'] = 'ISC'
                xdr['msgType'] = 1021
                xdr['dir'] = '0'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in scscfIP: scscfIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in asIP:    asIP.append(xdr['dip'][-1])
                if(len(xdr.get('Routes',['',''])) == 2):
                    if(line_no+1 < len(invite_list) and xdr.get('Routes',['',''])[1] == invite_list[line_no+1].get('Routes',[''])[0]):
                        invite_list[line_no+1]['interface'] = 'ISC'
                        invite_list[line_no+1]['msgType'] = 1021
                        invite_list[line_no+1]['dir'] = '1'
                        invite_list[line_no+1]['keyword4'] = xdr['keyword4']
                        invite_list[line_no+1]['mode'] = 'Complete'
                        
                        if invite_list[line_no+1]['sip'][-1] not in asIP:       asIP.append(invite_list[line_no+1]['sip'][-1])
                        if invite_list[line_no+1]['dip'][-1] not in scscfIP:    scscfIP.append(invite_list[line_no+1]['dip'][-1])

            # mgcf: SCSCF -->MGCF, 可确定目标网元是MGCF，接口为Mg；源网元可能是SCSCF/ISBG/BGCF，标为SCSCF也没问题
            m = re.search(r'mgcf',xdr.get('Routes',[""])[0],flags=re.I)
            if m and len(xdr['sip'][-1]) == 4:
                xdr['interface'] = 'Mg2'
                xdr['dir'] = '1'
                xdr['msgType'] = 1065
                xdr['mode'] = 'Complete'
                if xdr['dip'][-1] not in mgcfIP:  mgcfIP.append(xdr['dip'][-1])

            # bgcf: SCSCF --> BGCF，可确定目标网元是BGCF，接口为Mi
            m = re.search(r'bgcf',xdr.get('Routes',[""])[0],flags=re.I)
            if m and len(xdr['sip'][-1]) == 4:
                xdr['interface'] = 'Mi'
                xdr['dir'] = '0'
                xdr['msgType'] = 1017
                xdr['mode'] = 'Complete'
                if xdr['dip'][-1] not in bgcfIP:  bgcfIP.append(xdr['dip'][-1])
            # isbg: SCSCF --> ISBG，可确定目标网元是 ISBG
            m = re.search(r'isbg',xdr.get('Routes',[""])[0],flags=re.I)
            if m and len(xdr['sip'][-1]) == 4:
                xdr['interface'] = 'ISBG'
                xdr['dir'] = '0'
                xdr['msgType'] = 1067
                xdr['mode'] = 'Complete'
                if xdr['dip'][-1] not in isbgIP:  isbgIP.append(xdr['dip'][-1])
            # # scpas: SCSCF --> SCP，可确定目标网元是 SCP，接口为ISC
            m = re.search(r'scpas',xdr.get('Routes',[""])[0],flags=re.I)
            if m and len(xdr['sip'][-1]) == 4:
                xdr['interface'] = 'ISC'
                xdr['dir'] = '0'
                xdr['msgType'] = 1021
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in scscfIP:  scscfIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in asIP:  asIP.append(xdr['dip'][-1])
            # sbc: XXX -->SBC，可确定目标网元是SBC，接口不确定
            m = re.search(r'sbc',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
            # atcf: eMSC -->SBC，可确定目标网元是ATCF即SBC，接口为 I2 (i2)；
            m = re.search(r'atcf.*\.org',xdr.get('Routes',[""])[0],flags=re.I)
            if m and len(xdr['sip'][-1]) == 4:
                if xdr['sip'][-1] in scscfIP:
                    xdr['interface'] = 'Mw2'
                    xdr['dir'] = '1'
                    if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
                else:
                    xdr['interface'] = 'I2'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1051
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in eMSCIP:     eMSCIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
            # term: SCSCF --> SBC --> (UE), 可确定目标网元是SBC，源网元是SCSCF，接口为Mw； ---- 这条没验证，只看到一个例子，可以先试着用；
            m = re.search(r'sip:term@',xdr.get('Routes',[""])[0],flags=re.I)
            if m and len(xdr['sip'][-1]) == 4:
                xdr['interface'] = 'Mw2'
                xdr['dir'] = '1'
                xdr['msgType'] = 1061
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in scscfIP:    scscfIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
            # scscf: 有两种情况，所以不判断源网元，标记目标网元为SCSCF；
            # [1] (UE) -> SBC -> SCSCF，可确定目标网元是SCSCF，源网元是SBC，接口为 Gm 或 GmOverGTP，可根据有无 GTP 封装来确定；
            # [2]             XXX -> SCSCF，接口不能确定（可能是Mw/ISC 等）；
            # m = re.search(r'scscf',Routes[0],flags=re.I)
            # if m:
            #     xdr['interface'] = 'Mw'
            #     xdr['dir'] = '0'
            #     if xdr['sip'][-1] not in scscfIP:  scscfIP.append(xdr['sip'][-1])
            #     if xdr['dip'][-1] not in scscfIP:  scscfIP.append(xdr['dip'][-1])

            # 各种AS（下面列表提供），有两种情况
            # [1]           SCSCF-> AS，可确定目标网元是SCSCF，源网元是AS，接口标为 ISC（可能是 ISC/Ma）；
            # [2] (MSC)->SBC->AS，并且 SIP.message 存在 "Target-Dialog:"头域，接口为 ATCF-SCCAS；
            if xdr['Target_Dialog']:
                xdr['interface'] = 'ATCF-SCCAS'
                xdr['dir'] = '0'
                xdr['msgType'] = 1059
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in eMSCIP:     eMSCIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])

    if Is_Routes_masked:
        for line_no, xdr in enumerate(invite_list):
            if(line_no < Mw3_no or xdr['mode'] == 'Complete' and len(xdr['sip'][-1]) == 4):
                continue

            orig_ioi = re.search('orig-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
            term_ioi = re.search('term-ioi=',"" if xdr['P_Charging_Vector'] == '' else xdr['P_Charging_Vector'],flags=re.I)
            if(orig_ioi != None and term_ioi != None and len(xdr.get('Routes',[""])[0]) > len(invite_list[line_no - 1].get('Routes',[""])[0]) and xdr['CallID'] == invite_list[line_no - 1]['CallID'] and invite_list[line_no - 1]['mode'] != 'Complete'):
                print("aaaa-aaaa")
                invite_list[line_no - 1]['interface'] = 'ISC'
                invite_list[line_no - 1]['msgType'] = 1021
                invite_list[line_no - 1]['dir'] = '1'
                invite_list[line_no - 1]['mode'] = 'Complete'
                if invite_list[line_no - 1]['sip'][-1] not in asIP:         asIP.append(invite_list[line_no - 1]['sip'][-1])
                if invite_list[line_no - 1]['dip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no - 1]['dip'][-1])
                xdr['interface'] = 'ISC'
                xdr['msgType'] = 1021
                xdr['dir'] = '0'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in scscfIP:      scscfIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in asIP:         asIP.append(xdr['dip'][-1])
            elif(term_ioi == None and len(xdr.get('Routes',[""])[0]) > len(invite_list[line_no - 1].get('Routes',[""])[0]) and xdr['RequestURI'] != invite_list[line_no - 1]['RequestURI'] and invite_list[line_no - 1]['mode'] != 'Complete'):
                print("aaaa-bbbb")
                if((line_no + 1 == len(invite_list)) or (line_no + 1 < len(invite_list)) and (invite_list[line_no + 1]['ts'][0]- xdr['ts'][0]> 3)):
                    print("aaaa-cccc")
                    invite_list[line_no - 1]['interface'] = 'ISC'
                    invite_list[line_no - 1]['msgType'] = 1021
                    invite_list[line_no - 1]['dir'] = '1'
                    invite_list[line_no - 1]['mode'] = 'Complete'
                    if invite_list[line_no - 1]['sip'][-1] not in asIP:         asIP.append(invite_list[line_no - 1]['sip'][-1])
                    if invite_list[line_no - 1]['dip'][-1] not in scscfIP:      scscfIP.append(invite_list[line_no - 1]['dip'][-1])
                    xdr['interface'] = 'Mw2'
                    xdr['msgType'] = 1061
                    xdr['dir'] = '1'
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in scscfIP:      scscfIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcCoreIP:    sbcCoreIP.append(xdr['dip'][-1])

msg_prc_dict = {1015: '3100', 1017: '3101', 1019: '3102', 1021: '3103', 1023: '3104', 1025: '3105', 1051: '3106', 1053: '3107', 1055: '3108', 1057: '3109', 1059: '3110', 1061: '3111', 1063: '3112', 1065: '3113', 1067: '3114', 1069: '3115',1071: '3116',1073:'3117',1075:'3118',1077:'3119',1079:'3120'}

def as_update():
    for line_no, xdr in enumerate(status.sipXDR):
        if(xdr['request'] == 'INVITE' and xdr['mode'] != 'Complete'):
            xdr['keyword4'] = tag_as(xdr.get('Routes',[""])[0])
            if(xdr['keyword4'] != ''):
                xdr['interface'] = 'ISC'
                xdr['msgType'] = 1021
                xdr['dir'] = '0'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in scscfIP: scscfIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in asIP:    asIP.append(xdr['dip'][-1])

            # mgcf: SCSCF -->MGCF, 可确定目标网元是MGCF，接口为Mg；源网元可能是SCSCF/ISBG/BGCF，标为SCSCF也没问题
            m = re.search(r'mgcf',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                xdr['interface'] = 'Mg2'
                xdr['dir'] = '1'
                xdr['msgType'] = 1065
                xdr['mode'] = 'Complete'
                if xdr['dip'][-1] not in mgcfIP:  mgcfIP.append(xdr['dip'][-1])

            # bgcf: SCSCF --> BGCF，可确定目标网元是BGCF，接口为Mi
            m = re.search(r'bgcf',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                xdr['interface'] = 'Mi'
                xdr['dir'] = '0'
                xdr['msgType'] = 1017
                xdr['mode'] = 'Complete'
                if xdr['dip'][-1] not in bgcfIP:  bgcfIP.append(xdr['dip'][-1])
            # isbg: SCSCF --> ISBG，可确定目标网元是 ISBG，接口为Mw
            m = re.search(r'isbg',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                xdr['interface'] = 'ISBG'
                xdr['dir'] = '0'
                xdr['msgType'] = 1067
                xdr['mode'] = 'Complete'
                if xdr['dip'][-1] not in isbgIP:  isbgIP.append(xdr['dip'][-1])
            # # scpas: SCSCF --> SCP，可确定目标网元是 SCP，接口为ISC
            m = re.search(r'scpas',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                xdr['interface'] = 'ISC'
                xdr['dir'] = '0'
                xdr['msgType'] = 1021
                xdr['mode'] = 'Complete'
                if xdr['dip'][-1] not in asIP:  asIP.append(xdr['dip'][-1])
            # sbc: XXX -->SBC，可确定目标网元是SBC，接口不确定
            m = re.search(r'sbc',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
            # atcf: eMSC -->SBC，可确定目标网元是ATCF即SBC，接口为 I2 (i2)；
            m = re.search(r'atcf.*\.org',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                if xdr['sip'][-1] in scscfIP:
                    xdr['interface'] = 'Mw2'
                    xdr['dir'] = '1'
                    if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
                else:
                    xdr['interface'] = 'I2'
                    xdr['dir'] = '0'
                    xdr['msgType'] = 1051
                    xdr['mode'] = 'Complete'
                    if xdr['sip'][-1] not in eMSCIP:     eMSCIP.append(xdr['sip'][-1])
                    if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
            # term: SCSCF --> SBC --> (UE), 可确定目标网元是SBC，源网元是SCSCF，接口为Mw； ---- 这条没验证，只看到一个例子，可以先试着用；
            m = re.search(r'sip:term@',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                xdr['interface'] = 'Mw2'
                xdr['dir'] = '1'
                xdr['msgType'] = 1061
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in scscfIP:    scscfIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in sbcCoreIP:  sbcCoreIP.append(xdr['dip'][-1])
            m = re.search(r'ibcf',xdr.get('Routes',[""])[0],flags=re.I)
            if m:
                if xdr['sip'][-1] in scscfIP:
                  xdr['interface'] = 'IBCF'
                  xdr['msgType'] = 1073
                  xdr['dir'] = '0'
                  xdr['mode'] = 'Complete'
                  if xdr['dip'][-1] not in ibcfIP:      ibcfIP.append(xdr['dip'][-1])

def pairing_sip():
    via_dict = {}
    for line_no, xdr in enumerate(status.sipXDR):
        if(xdr.get('mode',"None") == 'Complete' and xdr['request'] != ''):
            via_dict[xdr['branch']+str(xdr.get('gtp',False))+str(xdr.get('esp',False))] = line_no

    for line_no, xdr in enumerate(status.sipXDR):
        if(xdr.get('mode',"None") != 'Complete' and xdr['request'] == ''):
            request_line_no = via_dict.get(xdr['branch']+str(xdr.get('gtp',False))+str(xdr.get('esp',False)),None)
            if request_line_no != None:
                xdr['interface'] = status.sipXDR[request_line_no]['interface']
                xdr['dir'] = '1' if status.sipXDR[request_line_no]['dir'] == '0' else '0'
                xdr['msgType'] = int(status.sipXDR[request_line_no]['msgType']) - 1
                xdr['keyword4'] = status.sipXDR[request_line_no]['keyword4']
                xdr['mode'] = 'Complete'
                if(xdr.get('status1',"0") == ''):
                    xdr['Cause'] = ""
                    status_code = -1
                else:
                    xdr["Cause"] = int(xdr.get('status1',"0"))
                    status_code = int(xdr.get('status1',"0"))
                if(status_code >= 400):
                    xdr['SuccFlag'] = '2'
                else:
                    xdr['SuccFlag'] = '0'
                temp1 = status.sipXDR[request_line_no]['ts'][0]*1000000000+status.sipXDR[request_line_no]['ts'][1]
                temp2 = xdr['ts'][0]*1000000000+xdr['ts'][1]
                status.sipXDR[request_line_no]['Latency'] = str((temp2 - temp1)//1000000)
                if(status.sipXDR[request_line_no]['Latency'] == '0'):
                    status.sipXDR[request_line_no]['Latency'] = '1'

                string = xdr["interface"] +"|"+pcap.strinfo.sub('8',status.sipXDR[request_line_no]['imsi'])+'|'+str(status.sipXDR[request_line_no]['msisdn'])+'|'+str(status.sipXDR[request_line_no]['pt_tsn'])+'|'+str(status.sipXDR[request_line_no]['tid'])+'|'+str(status.sipXDR[request_line_no]['cgi'])+'|'+str(status.sipXDR[request_line_no]['tac'])+'|'+str(status.sipXDR[request_line_no]['Network'])+'|'+str(status.sipXDR[request_line_no]['sip'][-1])+'|'+str(status.sipXDR[request_line_no]['dip'][-1])+'|'+pcap.printTime(status.sipXDR[request_line_no]['ts'])+'|'+str(status.sipXDR[request_line_no]['SuccFlag'])+'|'+str(msg_prc_dict[status.sipXDR[request_line_no]['msgType']])+'|'+str(status.sipXDR[request_line_no]['Latency'])+'|'+str(status.sipXDR[request_line_no]['Timeout'])+'|'+str(status.sipXDR[request_line_no]['Retrs'])+'|'+str(status.sipXDR[request_line_no]['Cause'])
                status.sipLatency.append(string)

                if xdr['interface'] == 'GmOverGTP':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in ueIP:		 	ueIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in sbcRanIP:		sbcRanIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in ueIP:			ueIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in sbcRanIP:		sbcRanIP.append(xdr['sip'][-1])

                if xdr['interface'] == 'Gm':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in ueIP:			ueIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in sbcRanIP:		sbcRanIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in ueIP:			ueIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in sbcRanIP:		sbcRanIP.append(xdr['sip'][-1])

                if xdr['interface'] == 'Mw1':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in sbcCoreIP:		sbcCoreIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in icscfIP:		icscfIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in sbcCoreIP:		sbcCoreIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in icscfIP:		icscfIP.append(xdr['sip'][-1])

                if xdr['interface'] == 'Mw2':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in sbcCoreIP:		sbcCoreIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in scscfIP:		scscfIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in sbcCoreIP:		sbcCoreIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in scscfIP:		scscfIP.append(xdr['sip'][-1])

                if xdr['interface'] == 'Mw3':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in scscfIP:		scscfIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in icscfIP:		icscfIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in scscfIP:		scscfIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in icscfIP:		icscfIP.append(xdr['sip'][-1])

                if xdr['interface'] == 'ISC':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in scscfIP:		scscfIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in asIP:			asIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in scscfIP:		scscfIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in asIP:			asIP.append(xdr['sip'][-1])

                if xdr['interface'] == 'I2':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in eMSCIP:		eMSCIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in sbcCoreIP:		sbcCoreIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in eMSCIP:		eMSCIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in sbcCoreIP:		sbcCoreIP.append(xdr['sip'][-1])

                if xdr['interface'] == 'Mg1':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in mgcfIP:		mgcfIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in icscfIP:		icscfIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in mgcfIP:		mgcfIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in scscfIP:		scscfIP.append(xdr['sip'][-1])

                if xdr['interface'] == 'Mg2':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in mgcfIP:		mgcfIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in scscfIP:		scscfIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in mgcfIP:		mgcfIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in scscfIP:		scscfIP.append(xdr['sip'][-1])

                if xdr['interface'] == 'Mj':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in mgcfIP:		mgcfIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in bgcfIP:		bgcfIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in mgcfIP:		mgcfIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in bgcfIP:		bgcfIP.append(xdr['sip'][-1])

                if xdr['interface'] == 'Mi':
                    if xdr['dir'] == '0':
                        if xdr['sip'][-1] not in scscfIP:		scscfIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in bgcfIP:		bgcfIP.append(xdr['dip'][-1])
                    else:
                        if xdr['dip'][-1] not in scscfIP:		scscfIP.append(xdr['dip'][-1])
                        if xdr['sip'][-1] not in bgcfIP:		bgcfIP.append(xdr['sip'][-1])

def update_sip_list(invite_list):
    pairing_sip()
    pairing_sip()
    ip_as_dict = {}

    for line_no, xdr in enumerate(invite_list):
        if(xdr.get('keyword4','') != ''):
            if(xdr['dir'] == '0'):
                ip_as_dict[xdr['dip'][-1]] = xdr['keyword4']
            else:
                ip_as_dict[xdr['sip'][-1]] = xdr['keyword4']

    for line_no, xdr in enumerate(status.sipXDR):
        if(xdr.get('mode',"None") != 'Complete'):
            if(xdr['sip'][-1] in ueIP and xdr['dip'][-1] in sbcRanIP and xdr.get("gtp",False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1053
                else:
                    xdr['msgType'] = 1052
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in ueIP and xdr['sip'][-1] in sbcRanIP and xdr.get("gtp",False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1053
                else:
                    xdr['msgType'] = 1052
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in ueIP and xdr['dip'][-1] in sbcRanIP and xdr.get("esp",False)):
                xdr['interface'] = 'Gm'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1015
                else:
                    xdr['msgType'] = 1014
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in ueIP and xdr['sip'][-1] in sbcRanIP and xdr.get("esp",False)):
                xdr['interface'] = 'Gm'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1015
                else:
                    xdr['msgType'] = 1014
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in ueIP and xdr['dip'][-1] in sbcRanIP):
                xdr['interface'] = 'Gm'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1015
                else:
                    xdr['msgType'] = 1014
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in ueIP and xdr['sip'][-1] in sbcRanIP):
                xdr['interface'] = 'Gm'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1015
                else:
                    xdr['msgType'] = 1014
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in sbcCoreIP and xdr['dip'][-1] in icscfIP):
                xdr['interface'] = 'Mw1'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1025
                else:
                    xdr['msgType'] = 1024
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in sbcCoreIP and xdr['sip'][-1] in icscfIP):
                xdr['interface'] = 'Mw1'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1025
                else:
                    xdr['msgType'] = 1024
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in sbcCoreIP and xdr['dip'][-1] in scscfIP):
                xdr['interface'] = 'Mw2'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1061
                else:
                    xdr['msgType'] = 1060
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in sbcCoreIP and xdr['sip'][-1] in scscfIP):
                xdr['interface'] = 'Mw2'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1061
                else:
                    xdr['msgType'] = 1060
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in scscfIP and xdr['dip'][-1] in icscfIP):
                xdr['interface'] = 'Mw3'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1063
                else:
                    xdr['msgType'] = 1062
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in scscfIP and xdr['sip'][-1] in icscfIP):
                xdr['interface'] = 'Mw3'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1063
                else:
                    xdr['msgType'] = 1062
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in scscfIP and xdr['dip'][-1] in scscfIP):
                xdr['interface'] = 'Mw4'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1069
                else:
                    xdr['msgType'] = 1068
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in scscfIP and xdr['dip'][-1] in asIP):
                xdr['interface'] = 'ISC'
                xdr['dir'] = '0'
                xdr['keyword4'] = ip_as_dict.get(xdr['dip'][-1],'')
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1021
                else:
                    xdr['msgType'] = 1020
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in scscfIP and xdr['sip'][-1] in asIP):
                xdr['interface'] = 'ISC'
                xdr['dir'] = '1'
                xdr['keyword4'] = ip_as_dict.get(xdr['sip'][-1],'')
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1021
                else:
                    xdr['msgType'] = 1020
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in eMSCIP and xdr['dip'][-1] in sbcCoreIP):
                xdr['interface'] = 'I2'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1051
                else:
                    xdr['msgType'] = 1050
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in eMSCIP and xdr['sip'][-1] in sbcCoreIP):
                xdr['interface'] = 'I2'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1051
                else:
                    xdr['msgType'] = 1050
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in mgcfIP and xdr['dip'][-1] in icscfIP):
                xdr['interface'] = 'Mg1'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1023
                else:
                    xdr['msgType'] = 1022
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in mgcfIP and xdr['sip'][-1] in icscfIP):
                xdr['interface'] = 'Mg1'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1023
                else:
                    xdr['msgType'] = 1022
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in mgcfIP and xdr['dip'][-1] in scscfIP):
                xdr['interface'] = 'Mg2'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1065
                else:
                    xdr['msgType'] = 1064
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in mgcfIP and xdr['sip'][-1] in scscfIP):
                xdr['interface'] = 'Mg2'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1065
                else:
                    xdr['msgType'] = 1064
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in mgcfIP and xdr['dip'][-1] in bgcfIP):
                xdr['interface'] = 'Mj'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1019
                else:
                    xdr['msgType'] = 1018
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in mgcfIP and xdr['sip'][-1] in bgcfIP):
                xdr['interface'] = 'Mj'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1019
                else:
                    xdr['msgType'] = 1018
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in scscfIP and xdr['dip'][-1] in bgcfIP):
                xdr['interface'] = 'Mi'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1017
                else:
                    xdr['msgType'] = 1016
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in scscfIP and xdr['sip'][-1] in bgcfIP):
                xdr['interface'] = 'Mi'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1017
                else:
                    xdr['msgType'] = 1016
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in sbcCoreIP and xdr['dip'][-1] in SCCASIP):
                xdr['interface'] = 'ATCF-SCCAS'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1059
                else:
                    xdr['msgType'] = 1058
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in sbcCoreIP and xdr['sip'][-1] in SCCASIP):
                xdr['interface'] = 'ATCF-SCCAS'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1059
                else:
                    xdr['msgType'] = 1058
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in scscfIP and xdr['dip'][-1] in mrfcIP):
                xdr['interface'] = 'Mr'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1071
                else:
                    xdr['msgType'] = 1070
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in scscfIP and xdr['sip'][-1] in mrfcIP):
                xdr['interface'] = 'Mr'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1071
                else:
                    xdr['msgType'] = 1070
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in asIP and xdr['dip'][-1] in mrfcIP):
                xdr['interface'] = 'Mr'
                xdr['dir'] = '0'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1071
                else:
                    xdr['msgType'] = 1070
                xdr['mode'] = 'Complete'
            elif(xdr['dip'][-1] in asIP and xdr['sip'][-1] in mrfcIP):
                xdr['interface'] = 'Mr'
                xdr['dir'] = '1'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1071
                else:
                    xdr['msgType'] = 1070
                xdr['mode'] = 'Complete'
            elif(xdr['sip'][-1] in ibcfIP and xdr['dip'][-1] in ibcfIP):
                xdr['interface'] = 'Ici'
                xdr['dir'] = '0'
                xdr['msgType'] = 1077
                xdr['mode'] = 'Complete'
            # 之前没有相关数据时的临时处理，现已废弃
            # elif(xdr['dip'][-1] in scscfIP and xdr['sip'][-1] in ibcfIP):
            #     xdr['interface'] = 'IBCF'
            #     xdr['dir'] = '1'
            #     if(xdr['request'] != ''):
            #         xdr['msgType'] = 1073
            #     else:
            #         xdr['msgType'] = 1072
            #     xdr['mode'] = 'Complete'
            # Mw5的相关逻辑，暂时不做，到时逻辑有可能会调整
            # elif(xdr['sip'][-1] in icscfIP and xdr['dip'][-1] in ibcfIP and len(xdr['sip'][-1]) == 4):
            #     xdr['interface'] = 'Mw5'
            #     xdr['dir'] = '1'
            #     if(xdr['request'] != ''):
            #         xdr['msgType'] = 1075
            #     else:
            #         xdr['msgType'] = 1074
            #     xdr['mode'] = 'Complete'
            # elif(xdr['sip'][-1] in ibcfIP and xdr['dip'][-1] in icscfIP and len(xdr['sip'][-1]) == 4):
            #     xdr['interface'] = 'Mw5'
            #     xdr['dir'] = '0'
            #     if(xdr['request'] != ''):
            #         xdr['msgType'] = 1074
            #     else:
            #         xdr['msgType'] = 1075
            #     xdr['mode'] = 'Complete'

    for line_no, xdr in enumerate(status.sipXDR):
        if(xdr.get('mode',"None") != 'Complete'):
            xdr['interface'] = 'SIP'
            if(xdr['request'] != ''):
                xdr['msgType'] = 1057
            else:
                xdr['msgType'] = 1056            

            if(xdr['dip'][-1] in asIP or xdr['sip'][-1] in scscfIP):
                xdr['dir'] = '0'
            elif(xdr['sip'][-1] in asIP or xdr['dip'][-1] in scscfIP):
                xdr['dir'] = '1'
            else:
                if(xdr['request'] != ''):
                    xdr['dir'] = '0'
                else:
                    xdr['dir'] = '1'
        elif(xdr.get('mode',"None") != 'Complete' and len(xdr['sip'][-1]) != 4):
            if(xdr.get('gtp',False)):
                xdr['interface'] = 'GmOverGTP'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1053
                else:
                    xdr['msgType'] = 1052  
            else:
                xdr['interface'] = 'Gm'
                if(xdr['request'] != ''):
                    xdr['msgType'] = 1015
                else:
                    xdr['msgType'] = 1014
            if(len([x for x in xdr['sip'][-1] if x == 0]) < len([x for x in xdr['dip'][-1] if x == 0])):
                xdr['dir'] == '0'
            else:
                xdr['dir'] == '1'

    pairing_sip()
    pairing_sip()
    AS_dict = dict([(x['dip'][-1],xdr['keyword4']) for x in status.sipXDR if x['interface'] == 'ISC' and x['dir'] == '0' and x['keyword4'] != ''])
    for xdr in status.sipXDR:
        if(xdr['interface'] == 'Mr'):
            if(xdr['dir'] == '0'):
                if(xdr['sip'][-1] in scscfIP):
                    xdr['keyword4'] = "SCSCF"
                else:
                    xdr['keyword4'] = AS_dict.get(xdr['sip'][-1],'AS')
            else:
                if(xdr['dip'][-1] in scscfIP):
                    xdr['keyword4'] = "SCSCF"
                else:
                    xdr['keyword4'] = AS_dict.get(xdr['dip'][-1],'AS')
    return

def find_AS(invite_list):
    for line_no, xdr in enumerate(invite_list):
        if(xdr['mode'] != 'Complate' and line_no >= 1 and line_no + 1 < len(invite_list)):
            if(invite_list[line_no-1]['mode'] == 'Complete' and invite_list[line_no-1]['interface'] == 'ISC' and invite_list[line_no-1]['dir'] == '0'):
                if(invite_list[line_no+1]['mode'] == 'Complete' and invite_list[line_no+1]['interface'] == 'ISC' and invite_list[line_no+1]['dir'] == '0'):
                    if(xdr['branch'] in invite_list[line_no+1]['branch']):
                        xdr['interface'] = 'ISC'
                        xdr['msgType'] = 1021
                        xdr['dir'] = '1'
                        xdr['mode'] = 'Complete'
                        if xdr['sip'][-1] not in asIP:         asIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in scscfIP:      scscfIP.append(xdr['dip'][-1])
                elif(invite_list[line_no+1]['mode'] == 'Complete' and invite_list[line_no+1]['interface'] == 'Mi' and invite_list[line_no+1]['dir'] == '0'):
                    if(xdr['branch'] in invite_list[line_no+1]['branch']):
                        xdr['interface'] = 'ISC'
                        xdr['msgType'] = 1021
                        xdr['dir'] = '1'
                        xdr['mode'] = 'Complete'
                        if xdr['sip'][-1] not in asIP:         asIP.append(xdr['sip'][-1])
                        if xdr['dip'][-1] not in scscfIP:      scscfIP.append(xdr['dip'][-1])

sip_dict = {1014:{"interface": "Gm", "LeftNE": "SBC", "RightNE": "UE"}, 1015:{"interface": "Gm", "LeftNE": "UE", "RightNE": "SBC"}, 1016:{"interface": "Mi", "LeftNE": "BGCF", "RightNE": "SCSCF"}, 1017:{"interface": "Mi", "LeftNE": "SCSCF", "RightNE": "BGCF"}, 1018:{"interface": "Mj", "LeftNE": "BGCF", "RightNE": "MGCF"}, 1019:{"interface": "Mj", "LeftNE": "MGCF", "RightNE": "BGCF"}, 1020:{"interface": "ISC", "LeftNE": "AS", "RightNE": "SCSCF"}, 1021:{"interface": "ISC", "LeftNE": "SCSCF", "RightNE": "AS"}, 1022:{"interface": "Mg1", "LeftNE": "ICSCF", "RightNE": "MGCF"}, 1023:{"interface": "Mg1", "LeftNE": "MGCF", "RightNE": "ICSCF"}, 1024:{"interface": "Mw1", "LeftNE": "ICSCF", "RightNE": "SBC"}, 1025:{"interface": "Mw1", "LeftNE": "SBC", "RightNE": "ICSCF"}, 1060:{"interface": "Mw2", "LeftNE": "SCSCF", "RightNE": "SBC"}, 1061:{"interface": "Mw2", "LeftNE": "SBC", "RightNE": "SCSCF"}, 1062:{"interface": "Mw3", "LeftNE": "ICSCF", "RightNE": "SCSCF"}, 1063:{"interface": "Mw3", "LeftNE": "SCSCF", "RightNE": "ICSCF"}, 1068:{"interface": "Mw4", "LeftNE": "SCSCF", "RightNE": "SCSCF"}, 1069:{"interface": "Mw4", "LeftNE": "SCSCF", "RightNE": "SCSCF"}, 1064:{"interface": "Mg2", "LeftNE": "SCSCF", "RightNE": "MGCF"}, 1065:{"interface": "Mg2", "LeftNE": "MGCF", "RightNE": "SCSCF"}, 1066:{"interface": "ISBG", "LeftNE": "SCSCF", "RightNE": "ISBG"}, 1067:{"interface": "ISBG", "LeftNE": "SCSCF", "RightNE": "ISBG"}, 1050:{"interface": "I2", "LeftNE": "SBC", "RightNE": "EMSC"}, 1051:{"interface": "I2", "LeftNE": "EMSC", "RightNE": "SBC"}, 1052:{"interface": "S1", "LeftNE": "MME", "RightNE": "eNB"}, 1053:{"interface": "S1", "LeftNE": "eNB", "RightNE": "MME"}, 1054:{"interface": "S5s8", "LeftNE": "SGW", "RightNE": "PGW"}, 1055:{"interface": "S5s8", "LeftNE": "SGW", "RightNE": "PGW"}, 1056:{"interface": "SIP", "LeftNE": "AS", "RightNE": "SCSCF"}, 1057:{"interface": "SIP", "LeftNE": "SCSCF", "RightNE": "AS"}, 1058:{"interface": "ATCF_SCCAS", "LeftNE": "SCSCF", "RightNE": "AS"}, 1059:{"interface": "ATCF_SCCAS", "LeftNE": "SCSCF", "RightNE": "AS"}, 1070:{"interface": "Mr", "LeftNE": "MRFC", "RightNE": "AS"}, 1071:{"interface": "Mr", "LeftNE": "AS", "RightNE": "MRFC"}, 1072:{"interface": "IBCF", "LeftNE": "IBCF", "RightNE": "SCSCF"},1073:{"interface": "IBCF", "LeftNE": "SCSCF", "RightNE": "IBCF"},1074:{"interface": "Mw5", "LeftNE": "IBCF", "RightNE": "SCSCF"},1075:{"interface": "Mw5", "LeftNE": "SCSCF", "RightNE": "IBCF"},1076:{"interface": "Ici", "LeftNE": "IBCF", "RightNE": "IBCF"},1077:{"interface": "Ici", "LeftNE": "IBCF", "RightNE": "IBCF"},1078:{"interface": "AG", "LeftNE": "SCSCF", "RightNE": "AGCF"},1079:{"interface": "AG", "LeftNE": "GCF", "RightNE": "SCSCF"}}

def sequence_diagrams():
    MAX_CHAR = 40
    fp = open("c.txt",'w')
    fp1 = open("d.txt",'w')

    ip_dict = {}

    for line_no, xdr in enumerate(status.sipXDR):
        if(xdr['keyword4'] !=''):
            if(xdr['dir'] == '0'):
                ip_dict[xdr['dip'][-1]] = xdr['keyword4']
            else:
                ip_dict[xdr['sip'][-1]] = xdr['keyword4']

    for line_no, xdr in enumerate(status.sipXDR):
        msg_info = sip_dict[xdr['msgType']]
        if(xdr['dir'] == '0'):
            if(xdr['interface'] == 'SIP'):
                LeftNE = msg_info['LeftNE'].replace("-",'_')
                RightNE = msg_info['RightNE'].replace("-",'_')
                print("{},{}->{}:{}".format(msg_info['interface'],LeftNE,RightNE,xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp.write("{}->{}:{}_{}\n".format(LeftNE,RightNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp1.write("{}_{}={}_{},{}->{}:{}_{}\n".format(xdr['dir'],msg_info['interface'],xdr['sip'][-1],xdr['dip'][-1],LeftNE,RightNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
            elif(xdr['interface'] == 'Mr'):
                LeftNE = ("SCSCF" if xdr['keyword4'] == '' else xdr['keyword4']).replace("-",'_')
                RightNE = 'MRFC'.replace("-",'_')
                print("{},{}->{}:{}".format(msg_info['interface'],LeftNE,RightNE,xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp.write("{}->{}:{}_{}\n".format(LeftNE,RightNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp1.write("{}_{}={}_{},{}->{}:{}_{}\n".format(xdr['dir'],msg_info['interface'],xdr['sip'][-1],xdr['dip'][-1],LeftNE,RightNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
            else:
                LeftNE = ip_dict.get(xdr['sip'][-1],msg_info['LeftNE']).replace("-","_")
                RightNE = ip_dict.get(xdr['dip'][-1],msg_info['RightNE']).replace("-","_")
                print("{},{}->{}:{}".format(msg_info['interface'],LeftNE,RightNE,xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp.write("{}->{}:{}_{}\n".format(LeftNE,RightNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp1.write("{}_{}={}_{},{}->{}:{}_{}\n".format(xdr['dir'],msg_info['interface'],xdr['sip'][-1],xdr['dip'][-1],LeftNE,RightNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
        else:
            if(xdr['interface'] == 'SIP'):
                RightNE = msg_info['RightNE'].replace("-",'_')
                LeftNE = msg_info['LeftNE'].replace("-",'_')
                print("{},{}->{}:{}".format(msg_info['interface'],RightNE,LeftNE,xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp.write("{}->{}:{}_{}\n".format(RightNE,LeftNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp1.write("{}_{}={}_{},{}->{}:{}_{}\n".format(xdr['dir'],msg_info['interface'],xdr['sip'][-1],xdr['dip'][-1],RightNE,LeftNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
            elif(xdr['interface'] == 'Mr'):
                LeftNE = ("SCSCF" if xdr['keyword4'] == '' else xdr['keyword4']).replace("-",'_')
                RightNE = 'MRFC'.replace("-",'_')
                print("{},{}->{}:{}".format(msg_info['interface'],RightNE,LeftNE,xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp.write("{}->{}:{}_{}\n".format(RightNE,LeftNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp1.write("{}_{}={}_{},{}->{}:{}_{}\n".format(xdr['dir'],msg_info['interface'],xdr['sip'][-1],xdr['dip'][-1],RightNE,LeftNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
            else:
                RightNE = ip_dict.get(xdr['sip'][-1],msg_info['RightNE']).replace("-","_")
                LeftNE = ip_dict.get(xdr['dip'][-1],msg_info['LeftNE']).replace("-","_")
                print("{},{}->{}:{}".format(msg_info['interface'],RightNE,LeftNE,xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp.write("{}->{}:{}_{}\n".format(RightNE,LeftNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))
                fp1.write("{}_{}={}_{},{}->{}:{}_{}\n".format(xdr['dir'],msg_info['interface'],xdr['sip'][-1],xdr['dip'][-1],RightNE,LeftNE,xdr['id'],xdr['keyword1'][:MAX_CHAR]+xdr['keyword4']))

    fp.flush()
    fp.close()
    fp1.flush()
    fp1.close()

def check_xdr(id,mark):
    for xdr in status.sipXDR:
        if(xdr['id'] == id):
            print(mark, xdr['id'],xdr['interface'],xdr['keyword4'])

def find_SCSCF(invite_list):
    for line_no, xdr in enumerate(invite_list):
        m = re.search(r'scscf',xdr.get('Routes',[''])[0],flags=re.I)
        n = tag_as(xdr.get('Routes',[''])[0])
        if n:
            pass
        elif(m and xdr['mode'] != 'Complete'):
            if xdr['dip'][-1] not in scscfIP:      scscfIP.append(xdr['dip'][-1])
            if line_no==0: 
              xdr['interface'] = 'Mw2'
              xdr['dir'] = '0'  
              if xdr['sip'][-1] not in sbcCoreIP:      sbcCoreIP.append(xdr['sip'][-1])

def find_AG(invite_list):
    for xdr in invite_list:
        if xdr['Max_Forwards'] == 70 and 'agcf' in xdr['P_Access_Network_Info']:
            xdr['interface'] = 'AG'
            xdr['msgType'] = 1079
            xdr['dir'] = '0'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in agcfIP:        agcfIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in scscfIP:       scscfIP.append(xdr['dip'][-1])
            # 找到一条就不继续了，根据此xdr设置后续AG xdr的信息
            break
    for xdr in status.sipXDR:
        if xdr['mode'] == 'Complete': continue
        if xdr['sip'][-1] in agcfIP and xdr['dip'][-1] in scscfIP:
            xdr['interface'] = 'AG'
            xdr['msgType'] = 1079
            xdr['dir'] = '0'
            xdr['mode'] = 'Complete'
        elif xdr['sip'][-1] in scscfIP and xdr['dip'][-1] in agcfIP:
            xdr['interface'] = 'AG'
            xdr['msgType'] = 1078
            xdr['dir'] = '1'
            xdr['mode'] = 'Complete'

def find_ipv6():
    update_sip_list(status.sipXDR)
    for xdr in status.sipXDR:
        if(xdr['mode'] == 'Complete'):
            continue
        if(len(xdr['sip'][-1]) == 4):
            continue
        if(xdr['request'] == 'REGISTER'):
            if(xdr.get('gtp', False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
            else:
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
            xdr['dir'] = '0'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
        elif(xdr['request'] == 'INVITE'):
            if(xdr.get('gtp', False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
            else:
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
            if(xdr['P_Asserted_Identity'] != ""):
                xdr['dir'] = '1'
                if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])
            elif(xdr['P_Preferred_Identity'] != ""):
                xdr['dir'] = '0'
                if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
            else:
                xdr['dir'] = '0'
                if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
            xdr['mode'] = 'Complete'
        elif(xdr['Security_Verify'] != '' and xdr['request'] != ''):
            if(xdr.get('gtp', False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1053
            else:
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1015
            xdr['dir'] = '0'
            if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
            xdr['mode'] = 'Complete'

    update_sip_list(status.sipXDR)

    for xdr in status.sipXDR:
        if(len(xdr['sip'][-1]) == 4):
            continue
        if(xdr['mode'] == 'Complete'):
            continue
        else:
            if(xdr.get('gtp', False)):
                xdr['interface'] = 'GmOverGTP'
                xdr['msgType'] = 1052
            else:
                xdr['interface'] = 'Gm'
                xdr['msgType'] = 1014
            if len(xdr['sip'][-1]) == 4:
                sip = inet_ntoa(xdr['sip'][-1])
                dip = inet_ntoa(xdr['dip'][-1])
            elif len(xdr['sip'][-1]) == 16:
                sip = inet_ntop(AF_INET6, xdr['sip'][-1])
                dip = inet_ntop(AF_INET6, xdr['dip'][-1])
            if(len(sip) > len(dip)):
                xdr['dir'] = '0'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in ueIP:          ueIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['dip'][-1])
            else:
                xdr['dir'] = '1'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in sbcRanIP:      sbcRanIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in ueIP:          ueIP.append(xdr['dip'][-1])

def find_Ici(invite_list):
    first_isbc = None
    for xdr in invite_list:
        # 1.根据时间找到最早的一条callid以isbc开头的码流，同时是invite
        if(xdr['CallID'].startswith('isbc')):
            first_isbc = xdr
            # 如果是ipv6
            if(len(xdr['sip'][-1]) == 16):
                xdr['interface'] = 'Ici'
                xdr['msgType'] = 1077
                xdr['dir'] = '0'
                xdr['mode'] = 'Complete'
                if xdr['sip'][-1] not in ibcfIP:        ibcfIP.append(xdr['sip'][-1])
                if xdr['dip'][-1] not in ibcfIP:        ibcfIP.append(xdr['dip'][-1])
            print('found first isbc')
            break

    for xdr in invite_list:
        # invite_list已经按时间排序了，如果xdr是first_isbc则说明first_isbc之前的xdr已经找完了，后续的xdr不需要再找了，退出循环
        if first_isbc is None or xdr is first_isbc: break
        # 2.找到这条码流之前，calid相同，但没有isbc前缀，且是invite和ipv6的码流，将目标网元和源网元改为ibcf，接口改为Ici
        if(xdr['ts1'] < first_isbc['ts1'] and xdr['CallID'] == first_isbc['CallID'][4:] and len(xdr['sip'][-1]) == 16):
            xdr['interface'] = 'Ici'
            xdr['msgType'] = 1077
            xdr['dir'] = '0'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in ibcfIP:        ibcfIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in ibcfIP:        ibcfIP.append(xdr['dip'][-1])
            print('found ibcf',xdr['IPv6'])

    for xdr in invite_list:
        if xdr['mode'] == 'Complete': continue
        # ipv6且request uri前缀包含1241/1242/1243则是携号转网，来自外网 [1493]
        m = xdr['RequestURI'].split(':')[1][:4]
        if m in ['1241','1242','1243'] and len(xdr['sip'][-1]) == 16:
            xdr['interface'] = 'Ici'
            xdr['msgType'] = 1077
            xdr['dir'] = '0'
            xdr['mode'] = 'Complete'
            if xdr['sip'][-1] not in ibcfIP:        ibcfIP.append(xdr['sip'][-1])
            if xdr['dip'][-1] not in ibcfIP:        ibcfIP.append(xdr['dip'][-1])

def find_5GGmOverGTP():
    group = []
    gtp_list = []
    for xdr in status.sipXDR:
        if xdr['interface'] != 'GmOverGTP': continue
        gtp_list.append(xdr)
        # 第一次 或 ip对有任意一个不一样时（不考虑顺序） 追加分组
        if len(group) == 0 or all(xdr['sip'][0] not in a['ip_pair'] or xdr['dip'][0] not in a['ip_pair'] for a in group): 
            group.append({'ip_pair':[xdr['sip'][0],xdr['dip'][0]],'is_5g':False,'gtp_list':[]})

    # 根据ip对追加xdr
    for xdr in gtp_list:
        for item in group:
            if xdr['sip'][0] in item['ip_pair'] and xdr['dip'][0] in item['ip_pair']:
                item['gtp_list'].append(xdr)
                break
    
    # 第一条invite xdr，用来确定dir
    first_invite_xdr = None
    for item in group:
        for xdr in item['gtp_list']:
            if xdr['request'] == 'INVITE' and first_invite_xdr is None:
                first_invite_xdr = xdr
                # 主叫
                if xdr['Max_Forwards'] == 70: 
                    xdr['dir'] = 0
                else:
                    xdr['dir'] = 1
            if '3GPP-NR' in xdr['P_Access_Network_Info'] and item['is_5g'] == False:
                # 主叫
                if xdr['request'] == 'REGISTER' or xdr['request'] == 'INVITE' and xdr['Max_Forwards'] == 70:
                    item['is_5g'] = True
                # 被叫 与第一条invite xdr的ip对相反
                elif first_invite_xdr is not None and xdr['sip'][0] == first_invite_xdr['dip'][0] and xdr['dip'][0] == first_invite_xdr['sip'][0]:
                    item['is_5g'] = True

    # 查找5GGmOverGTP
    for item in group:
        for xdr in item['gtp_list']:
            # 根据第一条invite xdr的dir来纠正其他xdr的dir
            if first_invite_xdr is not None:
                # ip对相同则方向相同，反之则方向相反
                if xdr['sip'][0] == first_invite_xdr['sip'][0] and xdr['dip'][0] == first_invite_xdr['dip'][0]:
                    xdr['dir'] = first_invite_xdr['dir']
                elif xdr['sip'][0] == first_invite_xdr['dip'][0] and xdr['dip'][0] == first_invite_xdr['sip'][0]:
                    if first_invite_xdr['dir'] == 0:
                        xdr['dir'] = 1
                    else:
                        xdr['dir'] = 0
            if item['is_5g']: xdr['interface'] = '5GGmOverGTP'
            print('find_5GGmOverGTP',xdr['keyword1'],xdr['interface'],xdr['Max_Forwards'],xdr['P_Access_Network_Info'],xdr['dir'])

def find_duplicate_ip():
    # 正常情况下，一个ip不会被重复添加到多个网元ip列表中，如果发现则说明逻辑有问题，请排查
    ip_names = ['ueIP', 'sbcIP', 'sbcRanIP', 'sbcCoreIP', 'scscfIP', 'icscfIP', 'iscscfIP', 'asIP', 'mscIP', 'bgcfIP', 'mgcfIP', 'eMSCIP', 'bgcfIP', 'isbgIP', 'SCCASIP', 'mrfcIP', 'ibcfIP', 'agcfIP']
    ip_lists = [ueIP, sbcIP, sbcRanIP, sbcCoreIP, scscfIP, icscfIP, iscscfIP, asIP, mscIP, bgcfIP, mgcfIP, eMSCIP, bgcfIP, isbgIP, SCCASIP, mrfcIP, ibcfIP, agcfIP]
    # ip作为key，值为此ip出现过的网元ip列表的索引；例如：b'\n#\n\xa3'这个ip被重复添加到了ueIP和asIP中，那么all_ip_dict = {b'\n#\n\xa3': [0, 7]}
    all_ip_dict = {}
    duplicate_ips = []

    for i, ip_list in enumerate(ip_lists):
        for ip in ip_list:
            if ip in all_ip_dict:
                if ip not in duplicate_ips:
                    duplicate_ips.append(ip)
                all_ip_dict[ip].append(i)
            else:
                all_ip_dict[ip] = [i]
    
    if duplicate_ips:
        for ip in duplicate_ips:
            i_list = all_ip_dict[ip]
            list_names = [ip_names[index] for index in i_list]
            print(f"Duplicate ip {ip} in {', '.join(list_names)}")

# 后期根据session id分组，分别执行sipCorrelation方法
def sipCorrelation():
    flush_tcp_sip()
    status.sipXDR = sorted(status.sipXDR ,key = lambda x: x['ts'][0]*1000000000+x['ts'][1])
    regist_list = []
    for xdr in status.sipXDR:
        if(xdr['request'] in ('REGISTER','SUBSCRIBE','NOTIFY') and xdr.get('dup',False) == False):
            xdr['mode'] = 'None'
            regist_list.append(xdr)
    # registration
    find_registration(regist_list)
    message_list = []
    for xdr in status.sipXDR:
        if(xdr['request'] == 'MESSAGE' and xdr.get('dup',False) == False):
            xdr['mode'] = 'None'
            message_list.append(xdr)
    # message
    find_message(message_list)
    # call
    invite_list = []
    for xdr in status.sipXDR:
        if(xdr['request'] == 'INVITE' and xdr.get('dup',False) == False):
            xdr['mode'] = 'None'
            invite_list.append(xdr)

    # find Ici
    find_Ici(invite_list)
    find_AG(invite_list)
    find_ATCF_SCCAS_I2(invite_list)
    find_mgcf(invite_list)
    find_ICSCF(invite_list)
    find_SCSCF(invite_list)
    mo_leg(invite_list)
    mt_leg(invite_list)
    find_AS(invite_list)
    # find Mw2 ibcf.pcap文件第5帧
    as_update()
    # find Mw5
    update_sip_list(status.sipXDR)
    find_ipv6()
    update_sip_list(status.sipXDR)
    find_5GGmOverGTP()
    find_duplicate_ip()

    if(sys.argv[0][:7] == 'decode3'):
        sequence_diagrams()
    output_sip_xdr()
    return

def call_list_output(call_list):
    print(str(call_list).replace("'",'"'))
    return

def call_split():
    call_list = {"call_list": []}
    icid_dict = {}
    call_id_dict = {}
    session_id_dict = {}

    for xdr in status.sipXDR:
        xdr['icid'] = ''
        if(xdr['P_Charging_Vector'] != ''):
            m = re.match('icid-value=([^;]+)',xdr['P_Charging_Vector'])
            if m:
                icid_list = m.groups()
                if(len(icid_list) >= 1):
                    xdr['icid'] = icid_list[0]


    for xdr in status.sipXDR:
        call_id_dict['CallID'] = {'icid': [], 'Session_ID': []}

    for xdr in status.sipXDR:
        if(xdr['icid'] != ''):
            call_id_dict[xdr['CallID']]['icid'].append(xdr['icid'])
        if(xdr['Session_ID'] != ''):
            call_id_dict[xdr['CallID']]['Session_ID'].append(xdr['Session_ID'])
    
    for CallID in call_id_dict:
        call_id_dict[xdr['CallID']]['key'] = list(set(call_id_dict[xdr['CallID']]['icid'] + call_id_dict[xdr['CallID']]['Session_ID']))
    exit()

    for xdr in status.sipXDR:
        session_id_dict.setdefault(xdr['Session_ID'], []).append(xdr['id'])
        icid_dict.setdefault(xdr['icid'], []).append(xdr['id'])
        call_id_dict.setdefault(xdr['CallID'], []).append(xdr['id'])
    
    return

    call_list['call_list'].append({'start_time':'2022-10-24 09:26:04.326000', 'end_time':'2022-10-24 09:26:05.901000'})
    call_list['call_list'].append({'start_time':'2022-10-24 09:26:05.901000', 'end_time':'2022-10-24 09:26:06.888000'})
    call_list['call_list'].append({'start_time':'2022-10-24 09:26:06.888000', 'end_time':'2022-10-24 09:26:11.391000'})
    call_list_output(call_list)
    return

msg_msg_dict = {1014: 1014, 1015: 1015, 1016: 1016, 1017: 1017, 1018: 1018, 1019: 1019, 1020: 1020, 1021: 1021, 1022: 1022, 1023: 1023, 1024: 1024, 1025: 1025, 1050: 1050, 1051: 1051, 1052: 1052, 1053: 1053, 1054: 1054, 1055: 1055, 1056: 1056, 1057: 1057, 1058: 1020, 1059: 1021, 1060: 1024, 1061: 1025, 1062: 1024, 1063: 1025, 1064: 1022, 1065: 1023, 1066: 1024, 1067: 1025, 1068: 1024, 1069: 1025,1070: 1070,1071:1071,1072:1072,1073:1073,1074: 1074, 1075: 1075,1076: 1076, 1077: 1077,1078:1078,1079:1079}

def output_sip_xdr():
    global gmOutputFile,gtpgmOutputFile, mwOutputFile, iscOutputFile, miOutputFile, mjOutputFile, mgOutputFile, i2OutputFile, ipcfgOutputFile, sipOutputFile, ATCF_SCCASOutputFile,mrSCCASOutputFile
    global gmCPLatencyOutputFile, gtpgmCPLatencyOutputFile, mwCPLatencyOutputFile, iscCPLatencyOutputFile, miCPLatencyOutputFile, mjCPLatencyOutputFile, mgCPLatencyOutputFile, i2CPLatencyOutputFile, sipCPLatencyOutputFile, ATCF_SCCASCPLatencyOutputFile,mrCPLatencyOutputFile
    for xdr in status.sipXDR:
        a = pcap.printTime(status.sipXDR[0]['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        # callID -> IMSI
        if xdr['imsi'] == '0':
            callid = callidIMSI.get(xdr['CallID'],('0','0'))
            if callid != ('0','0'):
                xdr['imsi'] = callid[0]
                xdr['msisdn'] = callid[1]
        else:
            callidIMSI[xdr['CallID']] = (xdr['imsi'],xdr['msisdn'])

        # raw = ''.join(['{:02x}'.format(x) for x in xdr['RawData'][0]])
        raw = ''
        if len(xdr['RawData']) == 1:
            raw = ''.join(['{:02x}'.format(x) for x in xdr['RawData'][0]])
        else:
            for frag in xdr['RawData']:
                padding = '00'*(1600-len(frag))
                raw += ''.join(['{:02x}'.format(x) for x in frag]) + padding
        temp = xdr['msgType']
        xdr['msgType'] = msg_msg_dict[xdr['msgType']]
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+raw+'|'+xdr['RequestMethod']+'|'+xdr['RequestURI']+'|'+xdr['Sender']+'|'+xdr['Receiver']+'|'+xdr['CallID']+'|'+xdr['CSeq']+'|'+'\n'
        xdr['msgType'] = temp

        ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
        if(xdr['interface'] == 'GmOverGTP' or xdr['interface'] == '5GGmOverGTP'):
            if len(xdr['sip'][0]) == 4:
                sip = inet_ntoa(xdr['sip'][0])
                dip = inet_ntoa(xdr['dip'][0])
            elif len(xdr['sip'][0]) == 16:
                sip = inet_ntop(AF_INET6, xdr['sip'][0])
                dip = inet_ntop(AF_INET6, xdr['dip'][0])
        else:
            if len(xdr['sip'][-1]) == 4:
                sip = inet_ntoa(xdr['sip'][-1])
                dip = inet_ntoa(xdr['dip'][-1])
            elif len(xdr['sip'][-1]) == 16:
                sip = inet_ntop(AF_INET6, xdr['sip'][-1])
                dip = inet_ntop(AF_INET6, xdr['dip'][-1])
        if(xdr['imsi'] == '0'): xdr['imsi'] = ''
        if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
        calling_number = xdr['calling']
        called_number = xdr['called']
        if(len(xdr['calling']) >8 and xdr['calling'][:2] == '86'): calling_number = xdr['calling'][2:]
        if(len(xdr['called']) >8 and xdr['called'][:2] == '86'): called_number = xdr['called'][2:]

        status.file_mode_xdr.append('|'.join([xdr['id'],ts,str(xdr['imsi']),str(xdr['msisdn']),sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),xdr.get('Latency',''),xdr.get('Retrs',''),'','','','','',xdr['keyword1'],calling_number,called_number,xdr['keyword4'],xdr['CallID'],"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

        if(xdr['interface'] == 'Gm'):
            if gmOutputFile == None:
                gmOutputFile = open(os.path.join(status.sdlDirectory, 'ImsCP_Gm_Msg_'+b+'.tmp'),'w')
            gmOutputFile.writelines(string)
        # elif(xdr['interface'] == 'GmOverGTP'):
        elif(xdr['interface'] in ('GmOverGTP', '5GGmOverGTP')):
            if gtpgmOutputFile == None:
                gtpgmOutputFile = open(os.path.join(status.sdlDirectory, 'ImsCP_S1_Msg_'+b+'.tmp'),'w')
            gtpgmOutputFile.writelines(string)
        elif(xdr['interface'] in ('Mw1','Mw2','Mw3','Mw4','Mw5','ATCF-SCCAS')):
            if mwOutputFile == None:
                mwOutputFile = open(os.path.join(status.sdlDirectory, 'ImsCP_Mw_Msg_'+b+'.tmp'),'w')
            mwOutputFile.writelines(string)
        elif(xdr['interface'] in ('Mg1','Mg2','AG')):
            if mgOutputFile == None:
                mgOutputFile = open(os.path.join(status.sdlDirectory, 'ImsCP_Mg_Msg_'+b+'.tmp'),'w')
            mgOutputFile.writelines(string)
        elif(xdr['interface'] in ('ISC','SIP')):
            if iscOutputFile == None:
                iscOutputFile = open(os.path.join(status.sdlDirectory, 'ImsCP_ISC_Msg_'+b+'.tmp'),'w')
            iscOutputFile.writelines(string)
        elif(xdr['interface'] == 'Mi'):
            if miOutputFile == None:
                miOutputFile = open(os.path.join(status.sdlDirectory, 'ImsCP_Mi_Msg_'+b+'.tmp'),'w')
            miOutputFile.writelines(string)
        elif(xdr['interface'] == 'Mj'):
            if mjOutputFile == None:
                mjOutputFile = open(os.path.join(status.sdlDirectory, 'ImsCP_Mj_Msg_'+b+'.tmp'),'w')
            mjOutputFile.writelines(string)
        elif(xdr['interface'] == 'I2'):
            if i2OutputFile == None:
                i2OutputFile = open(os.path.join(status.sdlDirectory, 'ImsCP_I2_Msg_'+b+'.tmp'),'w')
            i2OutputFile.writelines(string)
        elif(xdr['interface'] == 'Mr'):
            if i2OutputFile == None:
                i2OutputFile = open(os.path.join(status.sdlDirectory, 'ImsCP_Mr_Msg_'+b+'.tmp'),'w')
            i2OutputFile.writelines(string)
        # elif(xdr['interface'] == 'IBCF'):
        elif(xdr['interface'] in ('IBCF','Ici')):
            if i2OutputFile == None:
                i2OutputFile = open(os.path.join(status.sdlDirectory, 'ImsCP_IBCF_Msg_'+b+'.tmp'),'w')
            i2OutputFile.writelines(string)
        else:
            print("Warning: unknown SIP interface:", xdr['interface'])

    for xdr in status.sipLatency:
        f = xdr.strip().split("|")
        if(f[0] == 'Gm'):
            if gmCPLatencyOutputFile == None:
                gmCPLatencyOutputFile = open(os.path.join(status.sdlDirectory, 'ImsRTI_Gm_CPLatency_'+b+'.tmp'),'w')
            gmCPLatencyOutputFile.writelines('|'.join(f[1:])+'\n')
        # elif(f[0] == 'GmOverGTP'):
        elif(f[0] in ('GmOverGTP', '5GGmOverGTP')):
            if gtpgmCPLatencyOutputFile == None:
                gtpgmCPLatencyOutputFile = open(os.path.join(status.sdlDirectory, 'ImsRTI_S1_CPLatency_'+b+'.tmp'),'w')
            gtpgmCPLatencyOutputFile.writelines('|'.join(f[1:])+'\n')
        elif(f[0] in ('Mw1','Mw2','Mw3','Mw4','Mw5','ATCF-SCCAS')):
            if mwCPLatencyOutputFile == None:
                mwCPLatencyOutputFile = open(os.path.join(status.sdlDirectory, 'ImsRTI_Mw_CPLatency_'+b+'.tmp'),'w')
            mwCPLatencyOutputFile.writelines('|'.join(f[1:])+'\n')
        elif(f[0] in ('Mg1','Mg2','AG')):
            if mgCPLatencyOutputFile == None:
                mgCPLatencyOutputFile = open(os.path.join(status.sdlDirectory, 'ImsRTI_Mg_CPLatency_'+b+'.tmp'),'w')
            mgCPLatencyOutputFile.writelines('|'.join(f[1:])+'\n')
        elif(f[0] in ('ISC','SIP','IBCF','Ici')):
            if iscCPLatencyOutputFile == None:
                iscCPLatencyOutputFile = open(os.path.join(status.sdlDirectory, 'ImsRTI_ISC_CPLatency_'+b+'.tmp'),'w')
            iscCPLatencyOutputFile.writelines('|'.join(f[1:])+'\n')
        elif(f[0] == 'Mi'):
            if miCPLatencyOutputFile == None:
                miCPLatencyOutputFile = open(os.path.join(status.sdlDirectory, 'ImsRTI_Mi_CPLatency_'+b+'.tmp'),'w')
            miCPLatencyOutputFile.writelines('|'.join(f[1:])+'\n')
        elif(f[0] == 'Mj'):
            if mjCPLatencyOutputFile == None:
                mjCPLatencyOutputFile = open(os.path.join(status.sdlDirectory, 'ImsRTI_Mj_CPLatency_'+b+'.tmp'),'w')
            mjCPLatencyOutputFile.writelines('|'.join(f[1:])+'\n')
        elif(f[0] == 'I2'):
            if i2CPLatencyOutputFile == None:
                i2CPLatencyOutputFile = open(os.path.join(status.sdlDirectory, 'ImsRTI_I2_CPLatency_'+b+'.tmp'),'w')
            i2CPLatencyOutputFile.writelines('|'.join(f[1:])+'\n')
        elif(f[0] == 'Mr'):
            if mrCPLatencyOutputFile == None:
                mrCPLatencyOutputFile = open(os.path.join(status.sdlDirectory, 'ImsRTI_Mr_CPLatency_'+b+'.tmp'),'w')
            mrCPLatencyOutputFile.writelines('|'.join(f[1:])+'\n')
        else:
            print("Warning: unknown SIP interface in latency:", f[0])

    if gmOutputFile != None:
        gmOutputFile.flush()
        gmOutputFile.close()
    if gtpgmOutputFile != None:
        gtpgmOutputFile.flush()
        gtpgmOutputFile.close()
    if mwOutputFile != None:
        mwOutputFile.flush()
        mwOutputFile.close()
    if mgOutputFile != None:
        mgOutputFile.flush()
        mgOutputFile.close()
    if iscOutputFile != None:
        iscOutputFile.flush()
        iscOutputFile.close()
    if miOutputFile != None:
        miOutputFile.flush()
        miOutputFile.close()
    if mjOutputFile != None:
        mjOutputFile.flush()
        mjOutputFile.close()
    if i2OutputFile != None:
        i2OutputFile.flush()
        i2OutputFile.close()
    if gmCPLatencyOutputFile != None:
        gmCPLatencyOutputFile.flush()
        gmCPLatencyOutputFile.close()
    if gtpgmCPLatencyOutputFile != None:
        gtpgmCPLatencyOutputFile.flush()
        gtpgmCPLatencyOutputFile.close()
    if mwCPLatencyOutputFile != None:
        mwCPLatencyOutputFile.flush()
        mwCPLatencyOutputFile.close()
    if mgCPLatencyOutputFile != None:
        mgCPLatencyOutputFile.flush()
        mgCPLatencyOutputFile.close()
    if iscCPLatencyOutputFile != None:
        iscCPLatencyOutputFile.flush()
        iscCPLatencyOutputFile.close()
    if miCPLatencyOutputFile != None:
        miCPLatencyOutputFile.flush()
        miCPLatencyOutputFile.close()
    if mjCPLatencyOutputFile != None:
        mjCPLatencyOutputFile.flush()
        mjCPLatencyOutputFile.close()
    if i2CPLatencyOutputFile != None:
        i2CPLatencyOutputFile.flush()
        i2CPLatencyOutputFile.close()
    if mrCPLatencyOutputFile != None:
        mrCPLatencyOutputFile.flush()
        mrCPLatencyOutputFile.close()

    for root, dirs, files in os.walk(status.sdlDirectory):
        for file_name in files:
            if(file_name[-4:] == '.tmp'):
                tmpFileName = os.path.join(root, file_name)
                datFileName = re.sub('tmp','dat',tmpFileName)
                if os.path.isfile(datFileName): os.remove(datFileName)
                os.renames(tmpFileName,datFileName)
    return

def headerString(string):
    return r"(?:"+string+r")\s*:\s*(.*)"

lastUpdateTime = 0

gmOutputFile = None
gtpgmOutputFile = None
mwOutputFile = None
iscOutputFile = None
miOutputFile = None
mjOutputFile = None
mgOutputFile = None
i2OutputFile = None
ipcfgOutputFile = None
sipOutputFile = None
ATCF_SCCASOutputFile = None
mrOutputFile = None

gmCPLatencyOutputFile = None
gtpgmCPLatencyOutputFile = None
mwCPLatencyOutputFile = None
iscCPLatencyOutputFile = None
miCPLatencyOutputFile = None
mjCPLatencyOutputFile = None
mgCPLatencyOutputFile = None
i2CPLatencyOutputFile = None
sipCPLatencyOutputFile = None
ATCF_SCCASCPLatencyOutputFile = None
mrCPLatencyOutputFile = None


gmCPLatency = {}
gtpgmCPLatency = {}
mwCPLatency = {}
mw1CPLatency = {}
mw2CPLatency = {}
mw3CPLatency = {}
mw4CPLatency = {}
iscCPLatency = {}
miCPLatency = {}
mjCPLatency = {}
mgCPLatency = {}
mg1CPLatency = {}
mg2CPLatency = {}
i2CPLatency = {}
sipCPLatency = {}
ATCF_SCCASCPLatency = {}

tcpsipFrags = {}
udpSipFrags = {}

sipXDR = []

ueIP = []
sbcIP = []
sbcRanIP = []
sbcCoreIP = []
scscfIP = []
icscfIP = []
iscscfIP = []
asIP = []
mscIP = []
bgcfIP = []
mgcfIP = []
eMSCIP = []
bgcfIP = []
isbgIP = []
SCCASIP = []
mrfcIP = []
ibcfIP = []
agcfIP = []


callidIMSI = {}
callidintstr = {}

sipRequest = r'(ACK|BYE|CANCEL|INFO|INVITE|MESSAGE|NOTIFY|OPTIONS|PRACK|REFER|REGISTER|SUBSCRIBE|UPDATE)\s[^\s]+\sSIP/2.0'
sipStatus = r'SIP/2.0\s+(\d{3})\s\b([^\r]+)\r'
regexSIPRequest = re.compile(sipRequest)
regexSIPStatus = re.compile(sipStatus)

headerRequestURI = r'(?:ACK|BYE|CANCEL|INFO|INVITE|MESSAGE|NOTIFY|OPTIONS|PRACK|REFER|REGISTER|SUBSCRIBE|UPDATE)\s+(\S+)\s+SIP/2.0'

headerTo = headerString(r'To|TO|t')
headerFrom = headerString(r'From|FROM|f')
headerCallID = headerString(r'Call-ID|i')
headerCSeq = headerString(r'CSeq')
headerContentType = headerString(r'Content-Type|c')
headerLength = headerString(r'Content-Length|l')

header_P_Preferred_Identity = headerString(r'P-Preferred-Identity')
header_P_Asserted_Identity = headerString(r'P-Asserted-Identity')
header_P_Access_Network_Info = headerString(r'P-Access-Network-Info')
header_P_Charging_Vector = headerString(r'P-Charging-Vector')
header_P_Called_Party_ID = headerString(r'P-Called-Party-ID')
header_Route = headerString(r'Route')
header_Record_Route = headerString(r'Record-Route')
header_Contact = headerString(r'Contact')

header_Security_Server = headerString(r'Security-Server')
header_Security_Client = headerString(r'Security-Client')
header_Security_Verify = headerString(r'Security-Verify')
header_Max_Forwards = headerString(r'Max-Forwards')
header_Authorization = headerString(r'Authorization')
header_Nonce = r'nonce=\"([^"]*)'
header_Target_Dialog = headerString(r'Target-Dialog')
header_via = headerString(r'Via|v')
header_PEM = headerString(r'P-Early-Media')
header_Session_ID = headerString(r'Session-ID')

regexRequestURI = re.compile(headerRequestURI)
regexHeaderTo = re.compile(headerTo)
regexHeaderFrom = re.compile(headerFrom)
regexHeaderCallID = re.compile(headerCallID)
regexHeaderCSeq = re.compile(headerCSeq)
regexHeaderContentType = re.compile(headerContentType)
regexheaderLength = re.compile(headerLength)

regexHeader_P_Preferred_Identity = re.compile(header_P_Preferred_Identity)
regexHeader_P_Asserted_Identity = re.compile(header_P_Asserted_Identity)
regexHeader_P_Access_Network_Info = re.compile(header_P_Access_Network_Info)
regexHeader_P_Charging_Vector = re.compile(header_P_Charging_Vector)
regexHeader_P_Called_Party_ID = re.compile(header_P_Called_Party_ID)
regexHeader_Route = re.compile(header_Route)
regexHeader_Record_Route = re.compile(header_Record_Route)
regexHeader_Contact = re.compile(header_Contact)

regexHeader_Security_Server = re.compile(header_Security_Server)
regexHeader_Security_Client = re.compile(header_Security_Client)
regexHeader_Security_Verify = re.compile(header_Security_Verify)
regexHeader_Max_Forwards = re.compile(header_Max_Forwards)
regexHeader_Authorization = re.compile(header_Authorization)
regexHeader_Nonce = re.compile(header_Nonce)
regexHeader_Target_Dialog = re.compile(header_Target_Dialog)
regexHeader_via = re.compile(header_via)
regexHeader_PEM = re.compile(header_PEM)
regexHeader_Session_ID = re.compile(header_Session_ID)