import sys
import os
import struct
import base64
import datetime
import time
import binascii
import pcap
import status
import re
from socket import inet_ntop, AF_INET6, inet_ntoa 
from collections import Counter

tag_name_list = ["universal", "application", "context-specific", "private",]
command_dict = {0: "addReq", 1: "moveReq", 2: "modReq", 3: "subtractReq", 4: "auditCapRequest", 5: "auditValueRequest", 6: "notifyReq", 7: "serviceChangeReq",}
reply_command_dict = {0: "addReply", 1: "moveReply", 2: "modReply", 3: "subtractReply", 4: "auditCapReply", 5: "auditValueReply", 6: "notifyReply", 7: "serviceChangeReply",}
megaco_command_dict = {'a': 'Add', 'A': 'Add', 'AV': 'AuditValue', 'mf': 'Modify', 'MF': 'Modify', 'n': 'Nodify', 'N': 'Nodify' ,'pr': 'Priority', 's': 'Subtract', 'S': 'Subtract', 'W-s': 'Wildcarded Subtract', 'W-S': 'Wildcarded Subtract'}

class asn1_tag:
    def __init__(self, raw):
        self.type = raw[0] >> 6
        self.type_name = tag_name_list[self.type]
        self.primitive = True if ((raw[0] >> 5) & 1) == 0 else False
        self.number = raw[0] & 0x1F
        self.name = "Unknown"
        if(self.number == 0x1F):
            self.number = 0
            pos = 1
            is_end = False
            while(is_end == False):
                tag_byte = raw[pos]
                self.number = self.number * 128 + (tag_byte & 0x7F)
                pos += 1
                if(tag_byte >> 7 == 0):
                    is_end = True
        else:
            pos = 1
        self.rawdata = raw[:pos]
        self.length = pos
    def set_name(self, name):
        self.name = name

    def __str__(self):
        return "type: {}, type_name: {}, primitive: {}, number: {}, name: {}".format(self.type,self.type_name,self.primitive,self.number, self.name)

    def __expr__(self):
        return "type: {}, type_name: {}, primitive: {}, number: {}".format(self.type,self.type_name,self.primitive,self.number)

    def __format__(self):
        return "type: {}, type_name: {}, primitive: {}, number: {}".format(self.type,self.type_name,self.primitive,self.number)

class asn1_length:
    def __init__(self, raw):
        pos = 0
        is_end = False
        self.length = raw[0]
        if(self.length > 128):           # short definite
            number_of_bytes = raw[0] % 128
            self.length = 0
            for i in raw[1:1 + number_of_bytes]:
                self.length = self.length * 256 + i
            self.rawdata = raw[:number_of_bytes + 1]
            self.length_length = number_of_bytes + 1
        else:
            self.rawdata = raw[:1]
            self.length_length = 1
        
    def __str__(self):
        return "length: {}, length_length: {}".format(self.length,self.length_length)
    def __expr__(self):
        return "length: {}, length_length: {}".format(self.length,self.length_length)
    def __format__(self):
        return "length: {}, length_length: {}".format(self.length,self.length_length)

class asn1_obj:
    def __init__(self, raw):
        pos = 0
        tag = asn1_tag(raw)
        self.tag_rawdata = raw[pos:pos+tag.length]
        pos += tag.length
        tag_length = asn1_length(raw[pos:])
        self.length_rawdata = raw[pos:pos+tag_length.length_length]
        pos += tag_length.length_length
        self.tag = tag
        self.length = tag_length
        if(tag.primitive == True):
            tag_value = raw[pos:pos+tag_length.length]
            self.value = tag_value
            self.value_rawdata = raw[pos:pos+tag_length.length]
        else:
            self.value = []
            self.value_rawdata = raw[pos:pos+self.length.length]
            total_length = self.length.length
            pos = 0
            while(pos < total_length):
                result = asn1_obj(self.value_rawdata[pos:])
                self.value.append(result)
                pos += result.tag.length + result.length.length_length + result.length.length

    def __str__(self):
        result = []
        if(self.tag.primitive == True):
            result.append("{} {} {} {}".format(self.tag_rawdata.hex(), self.length_rawdata.hex(),self.value_rawdata.hex(),self.tag.name))
        else:
            result.append("{} {} {} {}".format(self.tag_rawdata.hex(), self.length_rawdata.hex(),self.value_rawdata.hex(),self.tag.name))
            for line_no,obj in enumerate(self.value):
                for line in str(obj).split("\n"):
                    result.append("    "+line)
        return "\n".join(result)

    def search(self, oid):
        if(oid == ""):
            return None
        head, sep, tail = oid.partition(".")
        if(head == ""):
            return None
        if(self.tag.primitive == True):
            if(self.tag.number == int(head)):
                if(tail == ""):
                    return self.value
                else:
                    return None
            else:
                return None 
        else:
            if(self.tag.number == int(head)):
                if(tail == ""):
                    return self.value
                else:
                    result_list = []
                    for obj in self.value:
                        result = obj.search(tail)
                        if(result == []):
                            pass
                        elif(result == None):
                            pass
                        else:
                            result_list.append(result)
                    if(result_list == []):
                        return None
                    else:
                        return result_list
            else:
                return None

def search_value(obj, oid):
    result_list = obj.search(oid)
    if(result_list == None):
        return None
    result = None
    while(type(result_list) == list and len(result_list) == 1):
        result_list = result_list[0]
    return result_list

def search_tag_number(obj, oid):
    result_list = obj.search(oid)
    if(result_list == None):
        return None
    result = None
    while(type(result_list) == list and len(result_list) == 1):
        result_list = result_list[0]
    if(type(result_list) == list):
        return result_list[0].tag.number
    else:
       return result_list.tag.number

def decode_asn1(raw):
    obj = asn1_obj(raw)
    try:
        mediagatewayID = search_value(obj,"16.1.1")
        ip_addr, port = "",""
        if(mediagatewayID.tag.number == 0):                # IPv4
            for my_obj in mediagatewayID.value:
                if(my_obj.tag.number == 0):
                    ip_addr = ".".join([str(x) for x in my_obj.value])
                elif(my_obj.tag.number == 1):
                    port = struct.unpack("!H", my_obj.value)[0]
        elif(mediagatewayID.tag.number == 1):              # IPv6
            for my_obj in mediagatewayID.value:
                if(my_obj.tag.number == 0):
                    ip_addr = ":".join([str(x) for x in my_obj.value])
                elif(my_obj.tag.number == 1):
                    port = struct.unpack("!H", my_obj.value)[0]
        mediagatewayID = ip_addr + ":" + str(port)
    except:
        mediagatewayID = ""

    try:
        transaction = search_tag_number(obj,"16.1.2.1.0")
        if transaction == 0:
            transaction = "T"
        else:
            transaction = "P"
        # print("transaction:",transaction)
    except:
        transaction = ""

    try:
        transactionID = search_value(obj,"16.1.2.1.0.0")
        transactionID = struct.unpack("!I",b'\0' + transactionID)[0]
        # print("transactionID:",transactionID)
    except:
        transactionID = ""
    
    try:
        context = search_value(obj,"16.1.2.1.0.1.16.0")
        context = str(struct.unpack("B",context)[0])
        # print("context:",context)
    except:
        context = ""
    
    try:
        if transaction == 'T':
            command = search_tag_number(obj,"16.1.2.1.0.1.16.3.16.0")
            command = command_dict.get(command, "Unknown Command")
        else:
            command = search_tag_number(obj,"16.1.2.1.2.2.1.16.3")
            command = reply_command_dict.get(command, "Unknown Command")
        # print("command:",command)
    except:
        command = ""
    # print("aaa")

    return mediagatewayID,transaction,transactionID,context,command

def decodeMEGACO(xdr,raw,flush):
    xdr['display'] += ', MEGACO/H.248'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','4'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,0,''

    # decode one MEGACO message
    try:
        # m = re.match(r'!/2\s*(\[[^\]]+\]:\d+)\s*([TP])\s*=\s*(\d+)\s*{\s*C\s*=([^{]*){\s*(\w+)\s*=',raw.decode())
        m = re.match(r'!/2\s*(\[[^\]]+\]:\d+)\s*([TP])\s*=\s*(\d+)\s*{\s*C\s*=([^{]*){\s*(.*?)\s*=',raw.decode())
        m1 = re.search(r',\s*(.*?)\s*=',raw.decode())
        if m:
            mediagatewayID,transaction,transactionID,context,command = m.groups()
            if m1: command = m1.group(1)
            command = megaco_command_dict.get(command, "Unknown Command")
            if transaction == 'T':
                xdr['strValue'] = command + ' Request' 
            else:
                xdr['strValue'] = command + ' Reply' 
        else:
            print("xdr id:",xdr['id'])
            return
    except:
        mediagatewayID,transaction,transactionID,context,command = decode_asn1(raw)
        xdr['strValue'] = command
    
    xdr['transactionID'] = str(transactionID)
    if transaction == 'T':
        transaction = 'Request'
        xdr['msgType'] = 950
    else:
        transaction = 'Reply'
        xdr['msgType'] = 951

    if context == '$':
        context = '=Choose one'
    else:
        context = '='+context
    # command = re.sub(r'\bpr\s*=',r'Priority=',command)
    # command = re.sub(r'\b[aA]\s*=',r'Add=',command)
    # command = re.sub(r'\bmf\s*=',r'Modify=',command)
    # command = re.sub(r'\bMF\s*=',r'Modify=',command)
    # command = re.sub(r'\bN\s*=',r'Nodify=',command)
    # command = re.sub(r'\b[nN]\s*=',r'Nodify=',command)
    # command = re.sub(r'\bW-s\s*=',r'Wildcarded Subtract=',command)
    # command = re.sub(r'\bW-S\s*=',r'Wildcarded Subtract=',command)
    # command = re.sub(r'\bS\s*=',r'Subtract=',command)
    # command = re.sub(r'\bs\s*=',r'Subtract=',command)


    # xdr['strValue'] = context + ' ' + command
    if xdr['msgType'] == 950:
        print(xdr['display'],xdr['msgType'],transaction,context,command)
        xdr['dir'] = '0'
    elif xdr['msgType'] == 951:
        print(xdr['display'],xdr['msgType'],transaction,context,command)
        xdr['dir'] = '1'
    cacheMEGACOXDR(xdr)
    return

def outputMEGACOXDR(xdr):
    global megacoOutputFile,megacoCPLatencyOutputFile
    if xdr['msgType'] != 999:
        raw = ''
        if len(xdr['RawData']) == 1:
            raw = ''.join(['{:02x}'.format(x) for x in xdr['RawData'][0]])
        else:
            for frag in xdr['RawData']:
                padding = '00' * (1600 - len(frag))
                raw += ''.join(['{:02x}'.format(x) for x in frag]) + padding
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
        ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
        if len(xdr['sip'][-1]) == 4:
            sip = inet_ntoa(xdr['sip'][-1])
            dip = inet_ntoa(xdr['dip'][-1])
        elif len(xdr['sip'][-1]) == 16:
            sip = inet_ntop(AF_INET6, xdr['sip'][-1])
            dip = inet_ntop(AF_INET6, xdr['dip'][-1])
        xdr['interface'] = 'MEGACO'
        if(xdr['imsi'] == '0'): xdr['imsi'] = ''
        if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
        status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',xdr['transactionID'],"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

        if megacoOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            megacoOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_MEGACO_Msg_'+b+'.tmp')
            megacoOutputFile = open(megacoOutputFileName,'w')
            if megacoOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(megacoOutputFile)
        megacoOutputFile.writelines(string)

    # CPLatency
    if xdr['msgType'] in [950]:
        temp = megacoCPLatency.get((xdr['msgType'],xdr['transactionID'] ),0)
        if temp != 0:
            temp.append(xdr['ts'])
        else:
            temp = [xdr['ts']]
            megacoCPLatency[(xdr['msgType'],xdr['transactionID'])] = temp
    
    if xdr['msgType'] in [951]:
        pair = megacoPair[xdr['msgType']]
        for msg in pair:
            temp = megacoCPLatency.get((msg[0],xdr['transactionID']),0)
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
                del megacoCPLatency[(msg[0],xdr['transactionID'])]
                break
            else:
                del xdr
                return
    else:
        del xdr
        return
    xdr['MSC_ip'] = xdr['dip'][0]
    xdr['MGW_ip'] = xdr['sip'][0]
    xdr['msisdn'] = ''
    xdr['tid'] = ''
    xdr['tac'] = ''
    xdr['Timeout'] = ''
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['MSC_ip'])+'|'+str(xdr['MGW_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'

    if megacoCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        megacoCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'ImsRTI_MEGACO_CPLatency_'+b+'.tmp')
        megacoCPLatencyOutputFile = open(megacoCPLatencyOutputFileName,'w')
        if megacoCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(megacoCPLatencyOutputFile)
    megacoCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)

def cacheMEGACOXDR(xdr):
    outputMEGACOXDR(xdr)

def flushMEGACOXDR():
    for n in megacoXDR:
        outputMEGACOXDR(n)
    megacoXDR.clear()

megacoXDR = []

megacoOutputFile = None
megacoCPLatencyOutputFile = None

megacoCPLatency = {}

# Type	dir	msgNameUS	msgNameCN	 Notes
# 998 	0   megaco 	    megaco 	    Request->Reply

megacoPair = {}
#
megacoPair[951] = [[950, 998, 0]]
