import urllib.parse
import sys
import os
import struct
import base64
import datetime
import time
import binascii
from unittest import result
from urllib import response
import pcap
import status
from collections import Counter
import hpack
import json
import re
from socket import inet_ntop, AF_INET6, inet_ntoa  
from sbi_dict import sbi_dict

HTTP2_PREFACE = b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a'

http2_response_cache = []
http_response_list = {}

DEFAULT_SBI_MSG = "50500"
DEFAULT_SBI_RESP = "50511"

default_http_response = {"100":"Continue", "101":"Switching Protocols", "200":"OK", "201":"Created", "202":"Accepted", "203":"Non-Authoritative Information", "204":"No Content", "205":"Reset Content", "206":"Partial Content", "300":"Multiple Choices", "301":"Moved Permanently", "302":"Found", "303":"See Other", "304":"Not Modified", "305":"Use Proxy", "306":"Unused", "307":"Temporary Redirect", "400": "Bad request", "401": "Unauthorized", "403": "Forbidden", "404": "Not Found", "405": "Method Not Allowed", "408": "Request Timeout", "406": "406 Not Acceptable", "409": "Conflict", "410": "Gone", "411": "Length Required", "412": "Precondition Failed", "413": "Payload Too Large", "414": "URI Too Long", "415": "Unsupported Media Type", "429": "Too Many Requests", "500": "Internal Server Error", "501": "Not Implemented", "503": "Service Unavailable", "504": "Gateway Timeout",}

sbi_callback_reponse_dict = {"100":"Continue", "101":"Switching Protocols", "200":"OK", "201":"Created", "202":"Accepted", "203":"Non-Authoritative Information", "204":"No Content", "205":"Reset Content", "206":"Partial Content", "300":"Multiple Choices", "301":"Moved Permanently", "302":"Found", "303":"See Other", "304":"Not Modified", "305":"Use Proxy", "306":"Unused", "307":"Temporary Redirect", "402":"Payment Required", "407":"Proxy Authentication Required", "416":"Requested range not satisfiable", "417":"Expectation Failed", "502":"Bad Gateway", "505":"HTTP Version not supported",}

callback_url_dict = {}

# Flags
HTTP2_FLAG_END_STREAM = 0x01    # for DATA and HEADERS frames
HTTP2_FLAG_ACK = 0x01           # for SETTINGS and PING frames
HTTP2_FLAG_END_HEADERS = 0x04
HTTP2_FLAG_PADDED = 0x08
HTTP2_FLAG_PRIORITY = 0x20

http1_stream_dict = {}

http2_header_decoder_dict = {}
http2_stream_dict = {}


sbiOutputFile_dict = {}
sbiCPLatencyOutputFile_dict = {}

httpRequest = r'(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)\s([^\s]+)\sHTTP/1.1'
httpStatus = r'HTTP/1.1\s+(\d{3})\s\b([^\r]+)\r'
regexHTTPRequest = re.compile(httpRequest)
regexHTTPStatus = re.compile(httpStatus)
HTTP1Frags = {}

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

def matchHTTPHeader(raw):
    string1 = to_string(raw)
    fragHeader = False
    content_length = -1
    m = regexHTTPRequest.match(string1)
    if m != None:
        fragHeader = True
    else:
        m = regexHTTPStatus.match(string1)
        if m != None:
            fragHeader = True
        else:
            fragHeader = False
    if(fragHeader == True):
        content_length_match = re.search('\r\n(Content-Length|l)\s*:\s*(.*)',string1)
        if content_length_match:
            content_length = int(content_length_match.groups()[-1].strip())
    return fragHeader, content_length 

def checkHTTP1Packet(raw):
    is_fragments = False        # wether the packet is partial http/1.1 messages?
    http_message_list = []

    while True:
        header_raw, sep, Body_raw = raw.partition(b"\r\n\r\n")
        if(sep == b'\r\n\r\n'):
            fragHeader, content_length = matchHTTPHeader(header_raw)
            if(fragHeader == True and content_length <= len(Body_raw)):
                http_message_list.append(header_raw +sep+ Body_raw[:content_length])
                raw = Body_raw[content_length:]
                if(len(raw) == 0):
                    is_fragments = False
                    fragHeader = True
                    break
            else:
                is_fragments = True
                break
        else:
            is_fragments = True
            break

    return is_fragments,http_message_list

def decodeHTTP1(xdr,raw,flush):
    is_fragments,http_message_list = checkHTTP1Packet(raw)
    if(is_fragments):
        HTTP1Frags.setdefault(','.join(['_'.join(str(xdr['sip'])),str(xdr['sport']),''.join(str(xdr['dip'])),str(xdr['dport'])]),[]).append({"xdr": xdr, "raw":raw})
        print(xdr['display'],'HTTP/1.1 Fragment')
        temp_Frag_list = HTTP1Frags[','.join(['_'.join(str(xdr['sip'])),str(xdr['sport']),''.join(str(xdr['dip'])),str(xdr['dport'])])]
        if(len(temp_Frag_list) >=2 ):
            temp_raw = b"".join([x['raw'] for x in temp_Frag_list])
            is_fragments,http_message_list = checkHTTP1Packet(temp_raw)
            if(is_fragments):
                return
            else:
                xdr = temp_Frag_list[0]['xdr']
                RawData = [b''.join([y for y in x['xdr']['RawData']]) for x in temp_Frag_list]
                xdr['RawData'] = RawData
                RawData1 = [b''.join([y for y in x['xdr']['RawData1']]) for x in temp_Frag_list]
                xdr['RawData1'] = RawData1
                decode_stream_http1(xdr,temp_raw,False)
                HTTP1Frags[','.join(['_'.join(str(xdr['sip'])),str(xdr['sport']),''.join(str(xdr['dip'])),str(xdr['dport'])])].pop()
    else:
        for http_raw in http_message_list:
            tempXDR = xdr.copy()
            decode_stream_http1(tempXDR,http_raw,False)
        del xdr

def flush_tcp_http1():
    for key in HTTP1Frags:
        sorted_list = sorted(HTTP1Frags[key], key = lambda x: x['xdr']['seq'])
        xdr1 = sorted_list[0]['xdr']
        raw1 = sorted_list[0]['raw']
        for record in sorted_list[1:]:
            xdr = record['xdr']
            raw = record['raw']
            if(xdr1 == None):
                xdr1 = xdr
                raw1 = raw
            elif(xdr1['seq']+xdr1['tcpPayloadLength'] == xdr['seq']):
                raw1 = raw1 + raw
                xdr1['RawData'] = xdr1['RawData'] + xdr['RawData']
                xdr1['RawData1'] = xdr1['RawData1'] + xdr['RawData1']
                is_fragments,sip_message_list = checkHTTP1Packet(raw1)
                if(is_fragments == False):
                    for sip_raw in sip_message_list:
                        tempXDR = xdr1.copy()
                        decode_stream_http1(tempXDR,sip_raw,True)
                        xdr1 = None
                        raw1 = b''
            else:
                decode_stream_http1(xdr1,raw1,True)
                xdr1 = xdr
                raw1 = raw
        if(xdr1 != None):
            decode_stream_http1(xdr1,raw1,True)

class HTTP2Exception(Exception):
    def __init__(self, name, reason):
        self.name = name
        self.reason = reason

def json_find_value(j, key, value = None):
    if(type(j) not in (dict, list)):
        return value
    for name in j:
        if(name == key):
            return j[name]
        elif(type(j[name]) == dict):
            value = json_find_value(j[name], key)
            if(value != None): return value
        elif(type(j[name]) == list):
            for item in j[name]:
                value = json_find_value(item, key)
                if(value != None): return value
    return value

def get_id_by_j(j):
    if j == None:
        return "","","",""
    imsi, imei, msisdn, suci = "","","",""
    if(isinstance(j,dict) or isinstance(j,list)):
        for f in j:
            if(isinstance(j,list)):
                imsi1, imei1, msisdn1, suci1 = get_id_by_j(f)
            elif(isinstance(j,dict)):
                imsi1, imei1, msisdn1, suci1 = get_id_by_j(j[f])
            if imsi1 != "":
                imsi = imsi1
            if imei1 != "":
                imei = imei1
            if msisdn1 != "":
                msisdn = msisdn1
            if suci1 != "":
                suci = suci1
    else:
        if isinstance(j,str):
            m = re.search(r'imsi-(\d+)',j)
            if m:
                imsi = m.group(1)
            m = re.search(r'imeisv-(\d+)',j)
            if m:
                imei = m.group(1)
            m = re.search(r'supi-(\d+)',j)
            if m:
                msisdn = m.group(1)
            m = re.search(r'suci-([0-9\-]+)',j)
            if m:
                suci = m.group(1)
    return imsi, imei, msisdn, suci

def get_id(headers,j):
    imsi, imei, msisdn, suci = "","","",""
    for n in headers:
        m = re.search(r'imsi-(\d+)',headers[n])
        if m:
            imsi = m.group(1)
        m = re.search(r'imeisv-(\d+)',headers[n])
        if m:
            imei = m.group(1)
        m = re.search(r'supi-(\d+)',headers[n])
        if m:
            msisdn = m.group(1)
        m = re.search(r'suci-([0-9\-]+)',headers[n])
        if m:
            suci = m.group(1)

    imsi1, imei1, msisdn1, suci1 = get_id_by_j(j)
    if imsi1 != "":
        imsi = imsi1
    if imei1 != "":
        imei = imei1
    if msisdn1 != "":
        msisdn = msisdn1
    if suci1 != "":
        suci = suci1
    return imsi, imei, msisdn, suci

def sbi_heuristic(xdr,headers,j):
    if(xdr['msgType'] == '50000' and j != None):
        m = re.search('/npcf-',j.get('resourceUri',""))
        if m:
            xdr['dir'] = '1'
            xdr['interface'] = 'N7'
            return sbi_callback_reponse_dict
        return None
    elif(xdr['interface'] == "SBI"):
        if(j == None):
            if(re.search('/terminate',headers.get(':path',"")) and re.search('/npcf-smpolicycontrol/notification/v1/sm-policies/',headers.get(':path',""))):
                xdr['interface'] = 'N5'
                xdr['dir'] = '1'
                xdr['msgType'] = '50190'    # SmPolicyControlTerminationRequestNotification
                return {'204':'No Content, Notification was succesful',}
            elif(re.search('/update',headers.get(':path',"")) and re.search('/npcf-smpolicycontrol/notification/v1/sm-policies/',headers.get(':path',""))):
                xdr['interface'] = 'N7'
                xdr['dir'] = '1'
                xdr['msgType'] = '50188'    # SMPolicyControl Update Notify
                return {'200':'OK. The current applicable values corresponding to the policy control request trigger is reported','204':'No Content, Notification was succesfull','400':'Bad Request.',}
        else:
            m = j.get('deregReason',None)
            if m:
                m = re.search('/amf-3gpp-access/',headers[':path'])
                if m:
                    xdr['interface'] = 'N8'
                    xdr['dir'] = '1'
                    xdr['msgType'] = '50080'
                    return {'204':'Successful Notification response','default':'Unexpected error',}
                m = re.search('/amf-non-3gpp-access/',headers[':path'])
                if m:
                    xdr['interface'] = 'N8'
                    xdr['dir'] = '1'
                    xdr['msgType'] = '50090'
                    return {'204':'Successful Notification response','default':'Unexpected error',}
                m = j.get('accessType',None)
                if m:
                    xdr['interface'] = 'N8'
                    xdr['dir'] = '1'
                    xdr['msgType'] = '50090'
                    return {'204':'Successful Notification response','default':'Unexpected error',}
            if(re.search('/update',headers.get(':path',"")) and j.get('resourceUri',None) and j.get('smPolicyDecision',None)):
                xdr['interface'] = 'N7'
                xdr['dir'] = '1'
                xdr['msgType'] = '50188'    # SmPolicyUpdateNotification
                return {'200':'OK. The current applicable values corresponding to the policy control request trigger is reported','204':'No Content, Notification was succesfull','400':'Bad Request.',}

def decode_5G_SBI(headers_list,body,xdr_list):
    global sbiCPLatencyOutputFile_dict
    if(len(xdr_list) == 1):
        xdr = xdr_list[0]
    elif(xdr_list[0]['id'] == xdr_list[1]['id']):
        xdr = xdr_list[0]
    else:
        xdr = xdr_list[0]
        RawData = []
        RawData1 = []
        for temp_xdr in xdr_list:
            RawData += temp_xdr['RawData']
            RawData1 += temp_xdr['RawData1']
        xdr['RawData'] = RawData
        xdr['RawData1'] = RawData1
    xdr['pt_tsn'],  xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0
    xdr['cgi'],xdr['intValue'],xdr['strValue']  = 0,0,''
    headers = dict(headers_list)

    # find the json body
    content_type = headers.get('content-type',None)
    json_body = None
    if(content_type == None):
        try:
            j = json.loads(body.decode("ascii")) if body != None else None
        except:
            j = None
    elif(content_type[:17] == "multipart/related"):
        boundary = re.search("(?<=boundary=).*",content_type).group().encode()
        pos = 0
        part_list = []
        boundary = b"--"+boundary
        boundary_length = len(boundary)
        j = None
        while(pos < len(body)):
            cur_left = body.find(boundary,pos)
            cur_right = body.find(boundary,pos+boundary_length)
            if(cur_right == -1):
                break
            part_list.append(body[cur_left+boundary_length:cur_right].strip())
            pos += cur_right
        for part in part_list:
            break_point = part.find(b"\r\n\r\n")
            multipart_body = part[break_point+4:]
            multipart_header_list = part[:break_point].strip().split(b"\r\n")
            multipart_header_dict = dict([x.replace(b' ',b'').split(b":") for x in multipart_header_list])
            content_type = multipart_header_dict.get(b'content-type',None)
            if(content_type == b'application/json'):
                json_body = multipart_body
            if(json_body != b''):
                j = json.loads(json_body.decode("ascii")) if json_body != None else None
            else:
                j = None
    elif(content_type in ('application/json' ,'application/merge-patch+json')):
        json_body = body
        j = None
        if(json_body != b''):
            if(json_body[0:2] == b'--'):
                length_of_json_body = len(json_body)
                length_of_boundary = json_body.find(b"\r\n")
                boundary = json_body[:length_of_boundary]

                pos1 = 0
                part_list = [] 
                while pos1 < length_of_json_body - 2 - length_of_boundary:
                    s = json_body[pos1:].find(boundary)
                    if(s == pos1):
                        pos1 = 2 + length_of_boundary
                    else:
                        part_list.append((pos1,pos1 + s - 2))
                        pos1 = pos1 + s + length_of_boundary + 2
                if(len(part_list) > 0):
                    for part in part_list:
                        pos_of_body = json_body[part[0]:part[1]].find(b'\r\n\r\n')
                        m = json_body[part[0]:part[0] + pos_of_body].find(b'application/json')
                        if m != -1:
                            j = json.loads(json_body[part[0] + pos_of_body + 4:part[1]].decode("ascii"))
            else:
                try:
                    print(json_body[-2:])
                    j = json.loads(json_body.replace(b"\xaa\xaa",b"__").replace(b"\x00",b"_").decode("ascii")) if json_body != None else None
                except:
                    j = None

        else:
            j = None
    else:
        print('Error, content-type is not "application/json" or "multipart/". content-type:', content_type)
        j = None
        
    print("json value:",j)

    xdr['imsi'], xdr['imei'], xdr['msisdn'], xdr['suci'] = get_id(headers, j)

    request = headers.get(':method',None)
    status1 = headers.get(':status',None)
    if(request != None):
        xdr['Cause'] = ""
        path = headers.get(":path","")
        xdr['strValue'] = request + " " + path
        xdr['Network'] = "5"
        xdr['dir'] = "0"
        xdr['msgType'] = DEFAULT_SBI_MSG
        xdr['interface'] = 'SBI'
        found_response = None
        result_list = []
        for p in sbi_dict:
            if(request == p[2].upper()):
                pattern = (p[0]+p[1]).replace("{apiRoot}","")   # delete {apiRoot}
                pattern = re.sub(r"{.*}",r".*", pattern)        # change {} to .* 
                m = re.match(pattern,path)
                if m:
                    result_list.append({"sbi_item":p,"matching_item":m})
        m, p, matching_length = None, None, 0
        for result in result_list:
            if matching_length < result["matching_item"].span()[1]:
                m = result["matching_item"]
                p = result["sbi_item"]
                matching_length = result["matching_item"].span()[1]
        if m:
            xdr['msgType'] = sbi_dict[p]['msgType']
            xdr['dir'] = sbi_dict[p]['dir']
            xdr['interface'] = sbi_dict[p]['interface']
            # callback_url_dict
            found_response = sbi_dict[p]['response']
            for callback_key in sbi_dict[p]["callbacks"]:
                url_template = callback_key[1]
                m = re.match(r"{[^#]+#/(\w+)}",url_template)
                if(m == None):
                    continue
                callback_url = m.groups()[0]
                value = json_find_value(j,callback_url)
                if(value != None):
                    m = re.match(r"({[^}]+})",url_template)
                    place_holder = m.groups()[0]
                    value1 = url_template.replace(place_holder,value)
                    callback_url_dict[(value1,callback_key[2])] = sbi_dict[p]["callbacks"][callback_key]
        if(xdr['interface'] == "SBI"):
            ip = ".".join([str(x) for x in xdr['dip'][0]])
            expected_url = "".join(["http://",ip,headers.get("host",""), headers.get(":host",""), headers.get(":path","")])
            for notification in callback_url_dict:
                if(notification[1].lower() == request.lower() and notification[0] == expected_url):
                    # {'interface': 'N8', 'dir': '1', 'msgType': '50013', 'response': {'204': 'Successful Notification response', 'default': 'Unexpected error'}}
                    xdr['msgType'] = callback_url_dict[notification]['msgType']
                    xdr['dir'] = callback_url_dict[notification]['dir']
                    xdr['interface'] = callback_url_dict[notification]['interface']
                    found_response = callback_url_dict[notification]['response']
        m = re.match("/[^/]+/v\d{1}/",path)
        if not m:
            xdr['dir'] = "1"
        else:
            m = re.match("/(\w+)-[^/]+/",path)
            if m:
                sbi_ip[xdr['dip'][0]] = m.group(1)
        
        if xdr['msgType'] == '50000':
            found_response1 = sbi_heuristic(xdr,headers,j)
            if found_response1:
                found_response = found_response1
        elif(xdr['interface'] == "SBI"):
            key = tuple(sorted([sbi_ip.get(xdr['sip'][0],''),sbi_ip.get(xdr['dip'][0],'')]))
            m = interface_dict.get(key,None)
            if m:
                xdr['interface'] = m[0]
                xdr['msgType'] = m[1]
            else:
                found_response = sbi_heuristic(xdr,headers,j)
        # found_response = sbi_heuristic(xdr,headers,j)
        http_response_list[(xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport'],xdr["stream_identifier"])] = {"msgType":xdr['msgType'],"interface":xdr['interface'],"ts":xdr["ts"],"dir":xdr["dir"],"response":found_response,'imsi':xdr['imsi'],'imei':xdr['imei'],'msisdn':xdr['msisdn'],'suci':xdr['suci']}

    elif(status1 != None):
        xdr['msgType'] = DEFAULT_SBI_RESP
        xdr['Cause'] = status1
        xdr['Network'] = "5"
        xdr['dir'] = "1"
        # get the request from http2 steam table
        http_response = http_response_list.get((xdr['dip'][0],xdr['sip'][0],xdr['dport'],xdr['sport'],xdr["stream_identifier"]),None)
        if(http_response == None):
            print("Error, http_response_list missed")
            http2_response_cache.append(xdr)
            # 特殊情况，处理没有请求消息只有响应消息且响应码为409的情况 interface: N11 dir: 0(AMF->SMF)；1446.pcap
            if status1 == '409':
                xdr['interface'] = 'N11'
                xdr['dir'] = '0'
                xdr['strValue'] = "{} {}".format(status1, default_http_response.get(status1,""))
                outputSBIXDR(xdr)
            return

        # fill the xdr
        request_msgtype = http_response['msgType']
        request_ts = http_response['ts']
        request_dir = http_response['dir']
        reposne_dir = "1" if request_dir == "0" else "0"
        #reponse_ts = xdr["ts"]

        xdr['dir'] = reposne_dir
        if http_response['imsi'] != "":
            xdr['imsi'] = http_response['imsi']
        if http_response['imei'] != "":
            xdr['imei'] = http_response['imei']
        if http_response['msisdn'] != "":
            xdr['msisdn'] = http_response['msisdn']
        if http_response['suci'] != "":
            xdr['suci'] = http_response['suci']

        # opeion 1: use 3GPP defined value
        response_msgtype = str(int(request_msgtype) + 1)
        if(http_response['response'] == None):
            xdr['strValue'] = "{} {}".format(status1, default_http_response.get(status1,""))
        else:
            xdr['strValue'] = "{} {}".format(status1, http_response['response'].get(status1,default_http_response.get(status1,"")))
            if xdr['strValue'] == '':
                xdr['strValue'] = http_response['response'].get('default',"")
        # option 2: use http2 decoded value
        # xdr['strValue'] = '{} {}'.format(status1, sbi_callback_reponse_dict.get(status1, xdr['strValue']))

        xdr['msgType'] = response_msgtype
        xdr['interface'] = http_response['interface']

        # delete the paired http2 stream
        http_response = http_response_list.get((xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport'],xdr["stream_identifier"]),None)
        if(http_response != None):
            http_response_list.pop((xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport'],xdr["stream_identifier"]))
            http_response = http_response_list.get((xdr['dip'][0],xdr['sip'][0],xdr['dport'],xdr['sport'],xdr["stream_identifier"]),None)
            if(http_response != None):
                http_response_list.pop((xdr['dip'][0],xdr['sip'][0],xdr['dport'],xdr['sport'],xdr["stream_identifier"]))


        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['Timeout'] = ''
        xdr['APN_Id'] = ''

        if(int(status1) < 400):
            xdr['SuccFlag'] = '0'
        else:
            xdr['SuccFlag'] = '2'
        xdr['prcType'] = str((int(xdr['msgType'])-50000)//2+6500)
        temp1 = request_ts[0]*1000000000+request_ts[1]
        temp2 = xdr['ts'][0]*1000000000+xdr['ts'][1]
        xdr['Latency'] = str((temp2 - temp1)//1000000)
        if(xdr['Latency'] == '0'):
            xdr['Latency'] = '1'
        xdr['Retrs'] = "0"
    
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+'|'+str(struct.unpack('!I',xdr['dip'][0][0:4])[0])+'|'+str(struct.unpack('!I',xdr['sip'][0][0:4])[0])+'|'+pcap.printTime(request_ts)+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'

        sbiCPLatencyOutputFile = sbiCPLatencyOutputFile_dict.get(xdr["interface"],None)

        if sbiCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            sbiCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_'+xdr['interface']+'_CPLatency_'+b+'.tmp')
            sbiCPLatencyOutputFile = open(sbiCPLatencyOutputFileName,'w')
            if sbiCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(sbiCPLatencyOutputFile)
                sbiCPLatencyOutputFile_dict[xdr["interface"]] = sbiCPLatencyOutputFile
        sbiCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)

    else:
        print("Error, http2 without :method and :status headers.")
        return
    
    # 如果n2SmInfoType有值，则赋值给xdr['strValue']
    if b'n2SmInfoType' in body:
        si = body.find(b'{')
        ei = body.rfind(b'}') + 1
        j = json.loads(body[si:ei])
        xdr['strValue'] = j.get('n2SmInfoType')
    
    print(xdr['display']+', '+xdr['interface']+', '+str(xdr['msgType']+', '+xdr['strValue']))
    outputSBIXDR(xdr)
    # header is the http2 header
    # j is the json
    return

def flush_http2_response_cache():
    for xdr in http2_response_cache:
        # get the request from http2 steam table
        http_response = http_response_list.get((xdr['dip'][0],xdr['sip'][0],xdr['dport'],xdr['sport'],xdr["stream_identifier"]),None)
        if(http_response == None):
            print("Error, http_response_list missed")
            return

        # fill the xdr
        request_msgtype = http_response['msgType']
        request_ts = http_response['ts']
        request_dir = http_response['dir']
        reposne_dir = "1" if request_dir == "0" else "0"
        #reponse_ts = xdr["ts"]

        xdr['dir'] = reposne_dir
        if http_response['imsi'] != "":
            xdr['imsi'] = http_response['imsi']
        if http_response['imei'] != "":
            xdr['imei'] = http_response['imei']
        if http_response['msisdn'] != "":
            xdr['msisdn'] = http_response['msisdn']
        if http_response['suci'] != "":
            xdr['suci'] = http_response['suci']

        # opeion 1: use 3GPP defined value
        response_msgtype = str(int(request_msgtype) + 1)
        if(http_response['response'] == None):
            xdr['strValue'] = "{} {}".format(xdr['Cause'], default_http_response.get(xdr['Cause'],""))
        else:
            xdr['strValue'] = "{} {}".format(xdr['Cause'], http_response['response'].get(xdr['Cause'],default_http_response.get(xdr['Cause'],"")))
            if xdr['strValue'] == '':
                xdr['strValue'] = http_response['response'].get('default',"")
        # option 2: use http2 decoded value
        # xdr['strValue'] = '{} {}'.format(status1, sbi_callback_reponse_dict.get(status1, xdr['strValue']))

        xdr['msgType'] = response_msgtype
        xdr['interface'] = http_response['interface']

        # delete the paired http2 stream
        http_response = http_response_list.get((xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport'],xdr["stream_identifier"]),None)
        if(http_response != None):
            http_response_list.pop((xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport'],xdr["stream_identifier"]))
            http_response = http_response_list.get((xdr['dip'][0],xdr['sip'][0],xdr['dport'],xdr['sport'],xdr["stream_identifier"]),None)
            if(http_response != None):
                http_response_list.pop((xdr['dip'][0],xdr['sip'][0],xdr['dport'],xdr['sport'],xdr["stream_identifier"]))

        xdr['tid'] = ''
        xdr['tac'] = ''
        xdr['Timeout'] = ''
        xdr['APN_Id'] = ''

        if(int(xdr['Cause']) < 400):
            xdr['SuccFlag'] = '0'
        else:
            xdr['SuccFlag'] = '2'
        xdr['prcType'] = str((int(xdr['msgType'])-50000)//2+6500)
        temp1 = request_ts[0]*1000000000+request_ts[1]
        temp2 = xdr['ts'][0]*1000000000+xdr['ts'][1]
        xdr['Latency'] = str((temp2 - temp1)//1000000)
        if(xdr['Latency'] == '0'):
            xdr['Latency'] = '1'
        xdr['Retrs'] = "0"
    
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+'|'+str(struct.unpack('!I',xdr['dip'][0][0:4])[0])+'|'+str(struct.unpack('!I',xdr['sip'][0][0:4])[0])+'|'+pcap.printTime(request_ts)+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'

        sbiCPLatencyOutputFile = sbiCPLatencyOutputFile_dict.get(xdr["interface"],None)

        if sbiCPLatencyOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            sbiCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_'+xdr['interface']+'_CPLatency_'+b+'.tmp')
            sbiCPLatencyOutputFile = open(sbiCPLatencyOutputFileName,'w')
            if sbiCPLatencyOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(sbiCPLatencyOutputFile)
                sbiCPLatencyOutputFile_dict[xdr["interface"]] = sbiCPLatencyOutputFile
        sbiCPLatencyOutputFile.writelines(string)
        status.file_mode_CPlatency.append(string)
        print(xdr['display']+', '+xdr['interface']+', '+str(xdr['msgType']+', '+xdr['strValue']))
        outputSBIXDR(xdr)

def outputSBIXDR(xdr):
    global sbiOutputFile_dict

    # msgType = interface_msgType.get(xdr['interface'], DEFAULT_SBI_MSG)
    # xdr['msgType'] = msgType if int(xdr['msgType'])%2 == 0 else str(int(msgType) + 1)

    xdr['strValue'] = urllib.parse.unquote(xdr['strValue'])
    xdr.setdefault('imsi','0')
    if xdr['imsi'] == '0': xdr['imsi'] = str(888880000000000)
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
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr["imsi"]),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    sbiOutputFile = sbiOutputFile_dict.get(xdr["interface"],None)

    if sbiOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        sbiOutputFileName = os.path.join(status.sdlDirectory, "NrCP_"+xdr['interface']+"_Msg_"+b+".tmp")
        sbiOutputFile = open(sbiOutputFileName,'w')
        if sbiOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(sbiOutputFile)
            sbiOutputFile_dict[xdr["interface"]] = sbiOutputFile
    sbiOutputFile.writelines(string)

def decode_stream_http1(xdr,raw,flush):
    stream_identifier = sum([x for x in xdr['sip'][-1]+xdr['dip'][-1]]+[xdr["sport"],xdr['dport']])
    header, sep, body = raw.partition(b"\r\n\r\n")
    header = header.decode()
    content_type = ""
    content_length = ""
    request = None
    status1 = None
    headers = []
    request = regexHTTPRequest.match(header)
    
    if request:
        method, path = request.groups()
    else:
        status1 = regexHTTPStatus.match(header)
        if status1:
            status_code, response_phrease = status1.groups()
        else:
            return
    for line in header.split("\r\n"):
        m = re.match(r"Content-Type\s*:\s*\b(.*)", line)
        if m:
            content_type = m.groups()[-1]
        m = re.match(r"Content-Length\s*:\s*\b(.*)", line)
        if m:
            content_length = m.groups()[-1]
    if(sep == b"\r\n\r\n"):
        end_stream = True
    else:
        if request or status:
            if content_type == "":
                content_type = "application/json"
            if content_length == "":
                content_length = "0"
            end_stream = True
        else:
            return
    if request:
        headers.append((':method',method))
        headers.append((':scheme', 'http'))
        headers.append((':path', path))
    else:
        headers.append((':status',status_code))
        headers.append(('content-type', content_type))
        headers.append(('content-length', content_length))

    xdr["stream_identifier"] = sum([x for x in xdr['sip'][-1]+xdr['dip'][-1]]+[xdr["sport"],xdr['dport']])
    key1 = (xdr['sip'][-1],xdr['dip'][-1],xdr['sport'],xdr['dport'],stream_identifier)
    key = key1
    http1_stream = http1_stream_dict.get(key1,None)
    if(http1_stream == None):
        key2 = (xdr['dip'][-1],xdr['sip'][-1],xdr['dport'],xdr['sport'],stream_identifier)
        key = key2
        http1_stream = http1_stream_dict.get(key2,None)
        if(http1_stream == None):
            key = key1
            http1_stream = {"headers":[], "raw":b"","xdr_list":[]}
            http1_stream_dict[key] = http1_stream
    http1_stream["headers"] += headers
    http1_stream["raw"] +=  body if body != None else b""
    http1_stream["xdr_list"].append(xdr)

    if(end_stream):    
        decode_5G_SBI(http1_stream["headers"],http1_stream["raw"],http1_stream["xdr_list"])
        http1_stream_dict.pop(key)

    return

def decode_stream_http2(xdr,raw,flush,stream_identifier,headers,end_stream,end_headers):
    xdr["stream_identifier"] = stream_identifier
    key1 = (xdr['sip'][-1],xdr['dip'][-1],xdr['sport'],xdr['dport'],stream_identifier)
    key = key1
    http2_stream = http2_stream_dict.get(key1,None)
    if(http2_stream == None):
        key2 = (xdr['dip'][-1],xdr['sip'][-1],xdr['dport'],xdr['sport'],stream_identifier)
        key = key2
        http2_stream = http2_stream_dict.get(key2,None)
        if(http2_stream == None):    # aaa should be deleted
            key = key1
            http2_stream = {"headers":[], "raw":b"","xdr_list":[]}
            http2_stream_dict[key] = http2_stream
    http2_stream["headers"] += headers
    http2_stream["raw"] +=  raw if raw != None else b""
    http2_stream["xdr_list"].append(xdr)

    if(end_stream):
        xdr_list = []
        for x in http2_stream["xdr_list"]:
            if x not in xdr_list:
                xdr_list.append(x)
        decode_5G_SBI(http2_stream["headers"],http2_stream["raw"],xdr_list)
        http2_stream_dict.pop(key)

    return

def decodeHTTP2(xdr,raw,flush):
    result = status.http2_buffer.get((xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport']),None)
    if(result != None):
        RawData = []
        RawData1 = []
        buffer = b""
        xdr_temp = result[0][0]
        for xdr1, buffer1 in result:
            buffer += buffer1
        raw1 = buffer + raw
        xdr_temp['RawData'] += xdr['RawData']
        xdr_temp['RawData1'] += xdr['RawData1']
    else:
        xdr_temp = xdr
        raw1 = raw
    pos = 0
    n = len(raw1)

    line1_pos = raw1.find(b'\r\n')
    is_http2 = False
    if(line1_pos != -1):
        try:
            line1 = raw1[:line1_pos].decode()
            request = regexHTTPRequest.match(line1)
            if request:
                is_http2 = False
            else:
                status1 = regexHTTPStatus.match(line1)
                if status1:
                    is_http2 = False
                else:
                    is_http2 = True
        except:
            is_http2 = True
    else:
        is_http2 = True

    if is_http2:
        if(n >= 24):
            if struct.unpack('24s',raw1[:24])[0] == HTTP2_PREFACE:
                print(xdr['display'],', Magic')
                pos += 24
                http2_header_decoder_dict[(xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport'])] = hpack.hpack.Decoder()
                http2_header_decoder_dict[(xdr['dip'][0],xdr['sip'][0],xdr['dport'],xdr['sport'])] = hpack.hpack.Decoder()
        trunk_list = []
        while pos < n:
            try:
                length = struct.unpack('!I',b'\x00'+raw1[pos:pos+3])[0]
                header_type = struct.unpack('!B',raw1[pos+3:pos+4])[0]
            except:
                break
            flags = struct.unpack('!B',raw1[pos+4:pos+5])[0]
            stream_identifier = struct.unpack('!I',raw1[pos+5:pos+9])[0]
            if(length + pos + 9 > len(raw1)):
                status.http2_buffer.setdefault((xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport']),[]).append((xdr, raw))
                break
            elif(length + pos + 9 == len(raw1)):
                trunk_list.append((xdr_temp,stream_identifier,header_type, raw1[pos: pos + length + 9]))
                for xdr_temp1,stream_identifier_temp1,header_type_temp1, raw_temp1 in trunk_list:
                    decoder[header_type_temp1](xdr_temp1, raw_temp1, flush)
                result = status.http2_buffer.get((xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport']),None)
                if(result != None):
                    del status.http2_buffer[(xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport'])]
                break
            else:
                trunk_list.append((xdr_temp,stream_identifier,header_type, raw1[pos: pos + length + 9]))
                pos += length + 9

    else:
        decode_stream_http1(xdr,raw1,flush)
    return xdr

def decode_flags(flags):
    flags_list = []
    flags_list += ["END_STREAM"] if (flags & HTTP2_FLAG_END_STREAM) else []
    flags_list += ["END_HEADERS"] if (flags & HTTP2_FLAG_END_HEADERS) else []
    flags_list += ["PADDED"] if (flags & HTTP2_FLAG_PADDED) else []
    return "|".join(flags_list)

def decodeDATA(xdr,raw,flush):
    length = struct.unpack('!I',b'\x00'+raw[0:3])[0]
    header_type = struct.unpack('!B',raw[3:4])[0]
    flags = struct.unpack('!B',raw[4:5])[0]
    stream_identifier = struct.unpack('!I',raw[5:9])[0]
    pos = 9
    if flags & HTTP2_FLAG_PADDED:
        if length == 0:
            raise HTTP2Exception('Missing padding length in PADDED frame')
        pad_length = struct.unpack('B', raw[pos:pos+1])[0]
        if length <= pad_length:
            raise HTTP2Exception('Missing padding bytes in PADDED frame')
        unpadded_data = raw[pos:-pad_length]
    else:
        unpadded_data = raw[pos:]
    print(xdr['display'],', Data Frame',", length:",length, ", flags:",flags,decode_flags(flags), ", stream_identifier:",stream_identifier,", unpadded_data:",unpadded_data)
    decode_stream_http2(xdr,unpadded_data,flush,stream_identifier,[],(flags & HTTP2_FLAG_END_STREAM) == HTTP2_FLAG_END_STREAM, (flags & HTTP2_FLAG_END_HEADERS) == HTTP2_FLAG_END_HEADERS)
    return xdr

def decodeHEADERS(xdr,raw,flush):
    length = struct.unpack('!I',b'\x00'+raw[0:3])[0]
    header_type = struct.unpack('!B',raw[3:4])[0]
    flags = struct.unpack('!B',raw[4:5])[0]
    stream_identifier = struct.unpack('!I',raw[5:9])[0]
    pos = 9
    if flags & HTTP2_FLAG_PADDED:
        if length == 0:
            raise HTTP2Exception('Missing padding length in PADDED frame')
        pad_length = struct.unpack('B', raw[pos:pos + 1])[0]
        if length <= pad_length:
            raise HTTP2Exception('Missing padding bytes in PADDED frame')
        unpadded_data = raw[pos:-pad_length]
    else:
        unpadded_data = raw[pos:]

    pos += 1

    if flags & HTTP2_FLAG_PRIORITY:
        if len(unpadded_data) < 5:
            raise HTTP2Exception('Missing stream dependency in HEADERS frame with PRIORITY flag')
        stream_dep = struct.unpack('!I',raw[pos:pos+4])[0]
        weight = struct.unpack('!B',raw[pos+4:pos+5])[0]
        exclusive = (stream_dep & 0x80000000) != 0
        stream_dep &= 0x7fffffff
        weight += 1
        block_fragment = unpadded_data[5:] 
    else:
        block_fragment = unpadded_data
    print(xdr['display'],', Headers Frame',", length:",length, ", flags:",flags,decode_flags(flags), ", stream_identifier:",stream_identifier,", unpadded_data:",unpadded_data,", block_fragment:",block_fragment)

    http2_decoder = http2_header_decoder_dict.get((xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport']),None)
    if(http2_decoder == None):
        http2_decoder = hpack.hpack.Decoder()
        http2_header_decoder_dict[(xdr['sip'][0],xdr['dip'][0],xdr['sport'],xdr['dport'])] = http2_decoder

    decoded_headers = http2_decoder.decode(block_fragment)
    decode_stream_http2(xdr,None,flush,stream_identifier,decoded_headers,(flags & HTTP2_FLAG_END_STREAM) == HTTP2_FLAG_END_STREAM, (flags & HTTP2_FLAG_END_HEADERS) == HTTP2_FLAG_END_HEADERS)
    return xdr

def decodePRIORITY(xdr,raw,flush):
    length = struct.unpack('!I',b'\x00'+raw[0:3])[0]
    header_type = struct.unpack('!B',raw[3:4])[0]
    flags = struct.unpack('!B',raw[4:5])[0]
    stream_identifier = struct.unpack('!I',raw[5:9])[0]
    pos = 9
    stream_dep = struct.unpack('!I',raw[pos:pos+4])[0]
    weight = struct.unpack('!B',raw[pos+4:pos+5])[0]
    exclusive = (stream_dep & 0x80000000) != 0
    stream_dep &= 0x7fffffff
    weight += 1
    print(xdr['display'],', Priority Frame',", exclusive:",exclusive, ", stream_dep:",stream_dep, ", weight:",weight)
    return None

def decodeRST_STREAM(xdr,raw,flush):
    length = struct.unpack('!I',b'\x00'+raw[0:3])[0]
    header_type = struct.unpack('!B',raw[3:4])[0]
    flags = struct.unpack('!B',raw[4:5])[0]
    stream_identifier = struct.unpack('!I',raw[5:9])[0]
    if length != 4:
        raise HTTP2Exception('Invalid number of bytes in RST_STREAM frame (must be 4)')
    error_code = struct.unpack('!I', raw[9:])[0]
    print(xdr['display'],', RST_STREAM Frame',", error_code:", error_code)
    return None

def decodeSETTINGS(xdr,raw,flush):
    length = struct.unpack('!I',b'\x00'+raw[0:3])[0]
    header_type = struct.unpack('!B',raw[3:4])[0]
    flags = struct.unpack('!B',raw[4:5])[0]
    stream_identifier = struct.unpack('!I',raw[5:9])[0]
    if(length != 0):
        identifier = struct.unpack('!H',raw[9:11])[0]
        value = struct.unpack('!I',raw[11:15])[0]
    else:
        identifier = ''
        value = ''
    print(xdr['display'],', Setting Frame',", identifier:", identifier, ", value:", value)
    return None

def decodePUSH_PROMISE(xdr,raw,flush):
    length = struct.unpack('!I',b'\x00'+raw[0:3])[0]
    header_type = struct.unpack('!B',raw[3:4])[0]
    flags = struct.unpack('!B',raw[4:5])[0]
    stream_identifier = struct.unpack('!I',raw[5:9])[0]
    pos = 9
    if flags & HTTP2_FLAG_PADDED:
        if length == 0:
            raise HTTP2Exception('Missing padding length in PADDED frame')
        pad_length = struct.unpack('B', raw[pos:pos + 1])[0]
        if length <= pad_length:
            raise HTTP2Exception('Missing padding bytes in PADDED frame')
        unpadded_data = raw[pos:-pad_length]
    else:
        unpadded_data = raw[pos:]

    pos += 1
    if len(unpadded_data) < 4:
        raise HTTP2Exception('Missing promised stream ID in PUSH_PROMISE frame')
    promised_id = struct.unpack('!I', unpadded_data[pos:pos+4])[0]
    block_fragment = unpadded_data[pos+4:]
    print(xdr['display'],', PushPromise Frame',", promised_id:", promised_id, ", block_fragment:", block_fragment)
    return

def decodePING(xdr,raw,flush):
    length = struct.unpack('!I',b'\x00'+raw[0:3])[0]
    header_type = struct.unpack('!B',raw[3:4])[0]
    flags = struct.unpack('!B',raw[4:5])[0]
    stream_identifier = struct.unpack('!I',raw[5:9])[0]
    pos = 9
    if length != 8:
        raise HTTP2Exception('Invalid number of bytes in PING frame (must be 8)')

    print(xdr['display'],', Ping Frame',", length:", length, ", data:", raw[9:].hex())
    return None

def decodeGOAWAY(xdr,raw,flush):
    length = struct.unpack('!I',b'\x00'+raw[0:3])[0]
    header_type = struct.unpack('!B',raw[3:4])[0]
    flags = struct.unpack('!B',raw[4:5])[0]
    stream_identifier = struct.unpack('!I',raw[5:9])[0]
    pos = 9
    if length < 8:
        raise HTTP2Exception('Invalid number of bytes in GO_AWAY frame')
    last_stream_id = struct.unpack('!I', raw[pos:pos+4])[0]
    error_code = struct.unpack('!I', raw[pos+4:pos+8])[0]
    debug_data = raw[pos+8:]

    print(xdr['display'],', GoAway Frame',", last_stream_id:", last_stream_id, ", error_code:", error_code, ", debug_data:", debug_data)
    return None

def decodeWINDOW_UPDATE(xdr,raw,flush):
    length = struct.unpack('!I',b'\x00'+raw[0:3])[0]
    header_type = struct.unpack('!B',raw[3:4])[0]
    flags = struct.unpack('!B',raw[4:5])[0]
    stream_identifier = struct.unpack('!I',raw[5:9])[0]
    pos = 9
    if length != 4:
        raise HTTP2Exception('Invalid number of bytes in WINDOW_UPDATE frame (must be 4)')
    window_increment = struct.unpack('!I', raw[9:])[0]

    print(xdr['display'],', WindowUpdate Frame',", window_increment:", window_increment)
    return None

def decodeCONTINUATION(xdr,raw,flush):
    length = struct.unpack('!I',b'\x00'+raw[0:3])[0]
    header_type = struct.unpack('!B',raw[3:4])[0]
    flags = struct.unpack('!B',raw[4:5])[0]
    stream_identifier = struct.unpack('!I',raw[5:9])[0]
    pos = 9
    block_fragment = raw[9:]

    print(xdr['display'],', Continuation Frame',", block_fragment:", block_fragment)
    return xdr

decoder = [decodeDATA, decodeHEADERS, decodePRIORITY, decodeRST_STREAM, decodeSETTINGS, decodePUSH_PROMISE, decodePING, decodeGOAWAY, decodeWINDOW_UPDATE, decodeCONTINUATION,]

stream_list = {}

sbi_ip = {}
interface_dict = {}
interface_dict[('namf','nausf')] = ('N12', '50502')
interface_dict[('','nausf')] = ('N12', '50502')
interface_dict[('nausf','nudm')] = ('N13', '50504')
interface_dict[('namf','nsmf')] = ('N11', '50506')
interface_dict[('namf','nudm')] = ('N8', '50508')
interface_dict[('nsmf','nudm')] = ('N10', '50510')
interface_dict[('nsmf','npcf')] = ('N7', '50512')
interface_dict[('namf','nsmsf')] = ('N20', '50514')
interface_dict[('nsmsf','nudm')] = ('N21', '50516')
interface_dict[('namf','nnssf')] = ('N22', '50518')
interface_dict[('','nnssf')] = ('N22', '50518')
interface_dict[('namf','nnrf')] = ('NRF', '50520')
interface_dict[('','nnrf')] = ('NRF', '50520')

