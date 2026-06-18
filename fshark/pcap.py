from email import header
import sys
import os
import struct
import base64
import datetime
import time
import re
from collections import Counter

def cvtInt16BE(bytes):
    value = struct.unpack('!H', bytes)[0]
    return value
def cvtInt16LE(bytes):
    value = struct.unpack('H', bytes)[0]
    return value
def cvtInt32BE(bytes):
    value = struct.unpack('!I', bytes)[0]
    return value
def cvtInt32LE(bytes):
    value = struct.unpack('I', bytes)[0]
    return value

def printTime(ts):
    year,month,day,hour,minute,second,msec = cvtTime(ts)
    msec_str = str(msec + 1000000000)[1:7]
    return str(year)+'-'+'{:02}'.format(month)+'-'+'{:02}'.format(day)+' '+'{:02}'.format(hour)+':'+'{:02}'.format(minute)+':'+'{:02}'.format(second)+'.'+msec_str

def cvtTime(ts):
    global locale_year,locale_month,locale_day,locale_hour,locale_minute,locale_second,temp_second
    sec = ts[0] - time.timezone + 94608000  # 356 * 24 * 60 * 60 total seconds per three year
    msec = ts[1]
    if sec == temp_second:
        return locale_year,locale_month,locale_day,locale_hour,locale_minute,locale_second,msec
    year_leap = sec//126230400              # (365+365+365+366) * 24 * 60 * 60 total seconds per four years
    year_sec = sec - year_leap * 126230400
    year = year_sec // 31536000             # 365 * 24 * 60 * 60 total seconds per year
    if year == 4:
        year = 3 + 1967 + year_leap*4
    else:
        year = year + 1967 + year_leap*4
    if year == 3 or year == 4:
        leap = 1
    else:
        leap = 0
    tempday = year_sec % 31536000 // 86400
    hour = year_sec % 86400 // 3600
    minute = year_sec % 3600 // 60
    second = year_sec % 60
    if tempday <= 31:
        month = 1
        day = tempday + 1
    elif tempday < leap + 59:
        month = 2
        day = tempday - leap - 31 + 1
    elif tempday < leap + 90:
        month = 3
        day = tempday - leap - 59 + 1
    elif tempday < leap + 120:
        month = 4
        day = tempday - leap - 90 + 1
    elif tempday < leap + 151:
        month = 5
        day = tempday - leap - 120 + 1
    elif tempday < leap + 181:
        month = 6
        day = tempday - leap - 151 + 1
    elif tempday < leap + 212:
        month = 7
        day = tempday - leap - 181 + 1
    elif tempday < leap + 243:
        month = 8
        day = tempday - leap - 212 + 1
    elif tempday < leap + 273:
        month = 9
        day = tempday - leap - 243 + 1
    elif tempday < leap + 304:
        month = 10
        day = tempday - leap - 273 + 1
    elif tempday < leap + 334:
        month = 11
        day = tempday - leap - 304 + 1
    else:
        month = 12
        day = tempday - leap - 334 + 1
    locale_year,locale_month,locale_day,locale_hour,locale_minute,locale_second,temp_second = year,month,day,hour,minute,second,sec
    return year,month,day,hour,minute,second,msec

def cvtTimeBE(bytes):
    sec = struct.unpack('!I', bytes[0:4])[0]
    msec = struct.unpack('!I', bytes[4:8])[0] * 1000
    return sec,msec
def cvtTimeLE(bytes):
    sec = struct.unpack('I', bytes[0:4])[0]
    msec = struct.unpack('I', bytes[4:8])[0] * 1000
    return sec,msec
def cvtTimeBENS(bytes):
    sec = struct.unpack('!I', bytes[0:4])[0]  # 
    msec = struct.unpack('!I', bytes[4:8])[0] #
    return sec,msec
def cvtTimeLENS(bytes):
    sec = struct.unpack('I', bytes[0:4])[0]   # !
    msec = struct.unpack('I', bytes[4:8])[0]  # !
    return sec,msec

def get_ip_address(raw, pos, ip_type):
    if(len(raw[pos:]) == 0):
        return "", "", 0
    if(ip_type == ""):
        ver = raw[pos] >> 4
        if(ver == 4):
            ip_type = "IPv4"
        else:
            ip_type = "IPv6"
    if(ip_type == "IPv4" and len(raw[pos:]) >20):
        header = struct.unpack('!B',raw[pos:pos + 1])[0]
        ihl = (header & 15) * 4
        header,tos,length,id,flagsByte,ttl,protocol,CRC,sip,dip = struct.unpack('!2B3H2BH4s4s',raw[pos:pos + 20])
        if(protocol == 6):
            return sip, dip, pos + ihl
        elif(protocol == 17):
            pos += ihl
            try:
                sport,dport,length,checksum = struct.unpack('!4H',raw[pos:pos + 8])
            except:
                return "", "", 0
            if(sport == 2152 and dport == 2152):
                pos += 8
                E = (raw[pos] >> 2) & 1
                S = (raw[pos] >> 1) & 1
                PN = raw[pos] & 1
                pos += 8       # GTP fixed header length: Flags, MsgType, TEID

                # 扩展部分以4个字节为一组占用空间。其中S占前两个字节，第三个字节是PN，左右一个字节是Next Extension Header Type
                if(S == 1 or PN == 1 or E == 1):
                    pos += 4
                if(E == 1):    # 仅仅GPRS使用
                    nextExtenstionHeaderType = raw[pos - 1]
                    while(nextExtenstionHeaderType != 0):
                        extenstinLength = raw[pos] * 4
                        pos += extenstinLength
                        nextExtenstionHeaderType = raw[pos - 1]
                if(pos + 20 + 8 < len(raw)):
                    sip, dip, pos = get_ip_address(raw,pos,"")
                    return sip, dip, pos
                else:
                    return "", "", 0

    elif(ip_type == "IPv6" and len(raw[pos:]) > 40):
        try:
            ver,tc,fl,payloadLength,nextHeader,Hop,sip,dip = struct.unpack('!2B2H2B16s16s',raw[pos:pos + 40])
        except:
            return "", "", 0
        version = ver>>4
        trafficClass = (ver & 15)*16 + tc >>4
        flowLabel = (tc & 15) * 256*256 + fl
        if(nextHeader == 6):
            return sip, dip, pos + 40
        elif(nextHeader == 17):
            pos += 40
            sport,dport,length,checksum = struct.unpack('!4H',raw[pos:pos + 8])
            if(sport == 2152 and dport == 2152):
                pos += 8 + 12
                sip, dip, pos = get_ip_address(raw,pos,"")
                return sip, dip, pos
    else:
        return "", "", 0

    return "", "", 0

def get_ip_address_offset(raw, pos, ip_type):
    if(ip_type == ""):
        ver = raw[pos] >> 4
        if(ver == 4):
            ip_type = "IPv4"
        else:
            ip_type = "IPv6"

    if(ip_type == "IPv4"):
        header = struct.unpack('!B',raw[pos:pos + 1])[0]
        ihl = (header & 15) * 4
        try:
            header,tos,length,id,flagsByte,ttl,protocol,CRC,sip,dip = struct.unpack('!2B3H2BH4s4s',raw[pos:pos + 20])
        except:
            return  "", "", 0, 0, 0
        offset = flagsByte & 0x1FFF
        more = (flagsByte>>13) & 1
        if(offset == 0  and more == 0):
            return "", "", 0, 0, 0
        else: 
            return sip, dip, id, offset, pos

    elif(ip_type == "IPv6"): 
        try:
            ver,tc,fl,payloadLength,nextHeader,Hop,sip,dip = struct.unpack('!2B2H2B16s16s',raw[pos:pos + 40])
        except:
            return "", "", 0, 0, 0
        version = ver>>4
        trafficClass = (ver & 15)*16 + tc >>4
        flowLabel = (tc & 15) * 256*256 + fl
        if(nextHeader == 44):
            pos += 40
            try:
                nextHeader,_,offset,identification = struct.unpack('!BBHI',raw[pos:pos + 8])
            except:
                return "", "", 0, 0, 0
            return sip, dip, identification, offset>>3, pos + 8
    return "", "", 0, 0, 0

def get_tcp_seq(raw, pos):
    sport, dport, seq = 0, 0, 0
    try:
        sport,dport,seq,ack,headerByte = struct.unpack('!2H2IB',raw[pos:pos + 13])
    except:
        return 0, 0, 0
    return sport, dport, seq

def skip_ethernet(raw, pos):
    pos = pos + 12
    if pos+2 > len(raw):
        return "", pos
    bytes = struct.unpack('!H',raw[pos :pos  + 2])[0]
    while pos < len(raw) - 2:
        if bytes == 33024:                       # 0x8100, vlan
            pos += 4
            bytes = struct.unpack('!H',raw[pos :pos + 2])[0]
        pos += 2
        if bytes == 2048:                        # 0x0800, IPv4
            return "IPv4", pos 
        elif bytes == 34525:                     # 0x86DD, IPv6
            return "IPv6", pos 
    return "", pos

def skip_linux_cooked(raw, pos):
    pos += 14
    if pos+2 > len(raw):
        return "", pos
    bytes = struct.unpack('!H',raw[pos:pos + 2])[0]
    pos += 2
    if bytes == 2048:                        # 0x0800, IPv4
        return "IPv4", pos
    elif bytes == 34525:                     # 0x86DD, IPv6
        return "IPv6", pos
    return "", pos

def get_tcp_ip_seq(frame):
    linkType = pcapFileHandles[frame[0]]['linktype']
    raw = frame[5][16:]
    pos = 0
    sip, dip, sport, dport, seq = "","",0,0,0
    if linkType == 1:                  # WTAP_ENCAP_ETHERNET
        ip_type, pos = skip_ethernet(raw, pos)

        if(ip_type != ""):
            sip, dip, pos = get_ip_address(raw, pos, ip_type)
            if(sip != ""):
                sport, dport, seq = get_tcp_seq(raw, pos)
                if(sport != 0):
                    return sip, dip, sport, dport, seq
    elif linkType == 10:               # WTAP_ENCAP_FDDI , wireshark show the number as 5, but I see 10
                                       # sample file: D:\Development\wireshark\tools\dftestfiles\nfs.pcap
        #ip.decodeIPv4(xdr,pcap.pcapRAW[16:])
        pass
    elif linkType == 101:              # WTAP_ENCAP_RAW_IP
        sip, dip, pos = get_ip_address(raw, pos, "")
        if(sip != ""):
            sport, dport, seq = get_tcp_seq(raw, pos)
            if(sport != 0):
                return sip, dip, sport, dport, seq

    elif linkType == 107:              # WTAP_ENCAP_FRAMERELAY
        #print('linkType: WTAP_ENCAP_FRAMERELAY')
        pass
    elif linkType == 113:              # WTAP_ENCAP_SLL
        ip_type, pos = skip_linux_cooked(raw, pos)
        if(ip_type != ""):
            sip, dip, pos = get_ip_address(raw, pos, ip_type)
            if(sip != ""):
                sport, dport, seq = get_tcp_seq(raw, pos)
                if(sport != 0):
                    return sip, dip, sport, dport, seq
    elif linkType == 177:              # WTAP_ENCAP_LINUX_LAPD
        #print('linkType: WTAP_ENCAP_LINUX_LAPD')
        pass
    elif linkType == 235:              # WTAP_ENCAP_DVB
        #print('linktype: WTAP_ENCAP_DVB')
        pass
    else:
        #print('Unknown linktype:',pcap.linktype)
        pass

    return "", "", 0, 0, 0

def get_ip_id_offset(frame):
    linkType = pcapFileHandles[frame[0]]['linktype']
    raw = frame[5][16:]
    pos = 0
    sip, dip, identification, offset, seq = "","",0,0,0
    if linkType == 1:                  # WTAP_ENCAP_ETHERNET
        ip_type, pos = skip_ethernet(raw, pos)

        if(ip_type != ""):
            sip, dip, identification, offset, pos = get_ip_address_offset(raw, pos, ip_type)
            if(sip != ""):
                return sip, dip, identification, offset, seq
    elif linkType == 10:               # WTAP_ENCAP_FDDI , wireshark show the number as 5, but I see 10
                                            # sample file: D:\Development\wireshark\tools\dftestfiles\nfs.pcap
        #ip.decodeIPv4(xdr,pcap.pcapRAW[16:])
        pass
    elif linkType == 101:              # WTAP_ENCAP_RAW_IP
        sip, dip, identification, offset, pos = get_ip_address_offset(raw, pos, "")
        if(sip != ""):
            return sip, dip, identification, offset, seq
    elif linkType == 107:              # WTAP_ENCAP_FRAMERELAY
        #print('linkType: WTAP_ENCAP_FRAMERELAY')
        pass
    elif linkType == 113:              # WTAP_ENCAP_SLL
        ip_type, pos = skip_linux_cooked(raw, pos)
        if(ip_type != ""):
            sip, dip, identification, offset, pos = get_ip_address_offset(raw, pos, ip_type)
            if(sip != ""):
                return sip, dip, identification, offset, seq
    elif linkType == 177:              # WTAP_ENCAP_LINUX_LAPD
        #print('linkType: WTAP_ENCAP_LINUX_LAPD')
        pass
    elif linkType == 235:              # WTAP_ENCAP_DVB
        #print('linktype: WTAP_ENCAP_DVB')
        pass
    else:
        #print('Unknown linktype:',pcap.linktype)
        pass

    return "", "", 0, 0, 0

def sort_input_list_by_TCP_seq(pcapInputList):
    tcp_session_dict = {}
    for frame_pos, frame in enumerate(pcapInputList):
        sip, dip, sport, dport, seq = get_tcp_ip_seq(frame)
        if(sip != ""):
            tcp_session_dict.setdefault((sip, dip, sport, dport),[]).append((seq,frame_pos))

    for session in tcp_session_dict:
        frame_no_list_orignal = tcp_session_dict[session]
        if(len(frame_no_list_orignal) == 1):
            continue

        sorted_frame_no_list = sorted(frame_no_list_orignal, key = lambda x: x[0])

        frame_list = [pcapInputList[x[1]] for x in sorted_frame_no_list]
        for line_no, (_, frame_pos) in enumerate(frame_no_list_orignal):
            pcapInputList[frame_pos] = frame_list[line_no]

    return pcapInputList

def sort_input_list_by_IP_frag(pcapInputList):
    ip_frag_dict = {}

    for frame_pos, frame in enumerate(pcapInputList):
        sip, dip, identification, offset,_ = get_ip_id_offset(frame)
        if(sip != "" and identification != 0):
            ip_frag_dict.setdefault((sip, dip, identification),[]).append((offset,frame_pos))
    for session in ip_frag_dict:
        frame_no_list_orignal = ip_frag_dict[session]
        if(len(frame_no_list_orignal) == 1):
            continue

        sorted_frame_no_list = sorted(frame_no_list_orignal, key = lambda x: x[0])

        frame_list = [pcapInputList[x[1]] for x in sorted_frame_no_list]
        for line_no, (_, frame_pos) in enumerate(frame_no_list_orignal):
            pcapInputList[frame_pos] = frame_list[line_no]

    return pcapInputList

def pcapFiles(fileList):
    global pcapInputList,totalLength,pcapRAW
    for file in fileList:
        versionMajor,versionMinor,thisZone,sigfigs,snaplen,linktype,fileHandle,fileLength,readInt16Bytes,readInt32Bytes,readTime = pcapFile(file)
        pcap = {'versionMajor': versionMajor,'versionMinor':versionMinor,'thisZone':thisZone,'sigfigs':sigfigs,'snaplen':snaplen,'linktype':linktype,'fileHandle':fileHandle,'fileLength':fileLength,'readInt16Bytes':readInt16Bytes,'readInt32Bytes':readInt32Bytes,'readTime':readTime}
        pcapFileHandles.append(pcap)
        pcapIdList.append(1)
        # print(len(pcapIdList)-1,str(file))
        if versionMajor == -1:
            record = {'time':-1,'RAW':None,'timeval':None,'recordCapLen':None,'recordLen':None}
        else:
            RAW,timeval,recordCapLen,recordLen = nextPcapPacket(pcap)
            if RAW == None:
                record = {'time':-1,'RAW':None,'timeval':None,'recordCapLen':None,'recordLen':None,'id':None}
            else:
                record = {'time':timeval[0]*1000000000+timeval[1],'RAW':RAW,'timeval':timeval,'recordCapLen':recordCapLen,'recordLen':recordLen,'id':1}
        pcapBytes.append(record)
    while True:
        m,timeStamp,timeval,recordCapLen,recordLen,id = nextPacket1()
        if timeval == None:
            break
        pcapInputList.append((m,timeStamp,timeval,recordCapLen,recordLen,pcapRAW,id))
    pcapInputList = sorted(pcapInputList,key=lambda x:x[1])
    pcapInputList = sort_input_list_by_IP_frag(pcapInputList)
    pcapInputList = sort_input_list_by_TCP_seq(pcapInputList)
    totalLength = len(pcapInputList)
    return 0
def nextPacket():
    global nextPos,totalLength,pcapRAW
    if nextPos < totalLength:
        nextPos += 1
        pcapRAW = pcapInputList[nextPos - 1][5]
        return pcapInputList[nextPos - 1][:-2]+pcapInputList[nextPos - 1][-1:]
    return None,None,None,None,None,None
def nextPacket1():
    global pcapRAW
    time = -2
    m = 0
    for n in range(0,len(pcapBytes)):
        if pcapBytes[n]['time'] == -1:
            continue
        if time == -2:
            time = pcapBytes[n]['time']
            m = n
            continue
        elif time > pcapBytes[n]['time']:
            time = pcapBytes[n]['time']
            m = n
    if time == -2:
        return None,None,None,None,None,None
    result = [m,pcapBytes[m]['time'],pcapBytes[m]['timeval'],pcapBytes[m]['recordCapLen'],pcapBytes[m]['recordLen'],pcapIdList[m]]
    pcapRAW = pcapBytes[m]['RAW']
    RAW,timeval,recordCapLen,recordLen = nextPcapPacket(pcapFileHandles[m])
    pcapIdList[m] += 1
    if RAW == None:
        record = {'time':-1,'RAW':None,'timeval':None,'recordCapLen':None,'recordLen':None,'id':None}
    else:
        record = {'time':timeval[0]*1000000000+timeval[1],'RAW':RAW,'timeval':timeval,'recordCapLen':recordCapLen,'recordLen':recordLen,'id':pcapIdList[m]}
    pcapBytes[m] = record
    return result

def pcapFile(pcapFileName):
    versionMajor,versionMinor,thisZone,sigfigs,snaplen,linktype = 0,0,0,0,0,0
    fileHandle,fileLength = 0,0
    readInt16Bytes,readInt32Bytes,readTime = 0,0,0
    if pcapFileName == None:
        return -1,0,0,0,0,0,0,0,0,0,0

    pcapFile = open(pcapFileName,'rb')
    if pcapFile == None:
        exit()

    statinfo = os.stat(pcapFileName)    # delete if catch something wired
    fileLength = statinfo.st_size       # delete if catch something wired
    
    fileHandle = pcapFile
    pcapFile.seek(0,2)
    fileLength = pcapFile.tell()
    pcapFile.seek(0,0)
    if fileLength <32:
        #print('fileLength:',fileLength,pcapFileName)
        return -1,0,0,0,0,0,0,0,0,0,0
    magicNumberStr = struct.unpack('!4s', pcapFile.read(4))[0]
    magicNumber = struct.unpack('!I', magicNumberStr)[0]

    if magicNumber == 2712847316:               # A1B2 C3D4
        readInt16Bytes = cvtInt16BE
        readInt32Bytes = cvtInt32BE
        readTime = cvtTimeBE
    elif magicNumber == 3569595041:             # D4C3 B2A1
        readInt16Bytes = cvtInt16LE
        readInt32Bytes = cvtInt32LE
        readTime = cvtTimeLE
    elif magicNumber == 2712812756:             # A1B2 3CD4
        readInt16Bytes = cvtInt16BE
        readInt32Bytes = cvtInt32BE
        readTime = cvtTimeBENS
    elif magicNumber == 3560747681:             # D43C B2A1
        readInt16Bytes = cvtInt16LE
        readInt32Bytes = cvtInt32LE
        readTime = cvtTimeLENS
    elif magicNumber == 1295823521:             # 4D3C B2A1
        readInt16Bytes = cvtInt16LE
        readInt32Bytes = cvtInt32LE
        readTime = cvtTimeLE
    elif magicNumber == 1295823521:             # 5843 5000
        readInt16Bytes = cvtInt16LE
        readInt32Bytes = cvtInt32LE
        readTime = cvtTimeLE
    else:
        #print('Not one of the magic numbers we recognized.',base64.b16encode(magicNumberStr))
        return -1,0,0,0,0,0,0,0,0,0,0

    temp = struct.unpack('!2s', pcapFile.read(2))[0]
    versionMajor = readInt16Bytes(temp)
    temp = struct.unpack('!2s', pcapFile.read(2))[0]
    versionMinor = readInt16Bytes(temp)
    temp = struct.unpack('!4s', pcapFile.read(4))[0]
    thisZone = readInt32Bytes(temp)
    temp = struct.unpack('!4s', pcapFile.read(4))[0]
    sigfigs = readInt32Bytes(temp)
    temp = struct.unpack('!4s', pcapFile.read(4))[0]
    snaplen = readInt32Bytes(temp)
    temp = struct.unpack('!4s', pcapFile.read(4))[0]
    linktype = readInt32Bytes(temp)

    # if linktype not in (1,101,113,177):
        # return
    # print(versionMajor,versionMinor,thisZone,sigfigs,snaplen,linktype,pcapFileName)
    return versionMajor,versionMinor,thisZone,sigfigs,snaplen,linktype,fileHandle,fileLength,readInt16Bytes,readInt32Bytes,readTime

def nextPcapPacket(pcap):
    # global versionMajor,versionMinor,thisZone,sigfigs,snaplen,linktype,fileHandle,fileLength
    # global readInt16Bytes,readInt32Bytes,readTime,pcapRAW
    if pcap['fileHandle'].tell() < pcap['fileLength']:
        try:
            pcapheader = pcap['fileHandle'].read(16)
            temp1 = struct.unpack('!8s', pcapheader[0:8])[0]
            timeval = pcap['readTime'](temp1)
            temp2 = struct.unpack('!4s', pcapheader[8:12])[0]
            recordCapLen = pcap['readInt32Bytes'](temp2)
            temp3 = struct.unpack('!4s', pcapheader[12:16])[0]
            recordLen = pcap['readInt32Bytes'](temp3)
            RAW=temp1+temp2+temp3+pcap['fileHandle'].read(recordCapLen)
        except struct.error:
            return None,None,None,None
        # if (recordCapLen != recordLen) or pcap['fileHandle'].tell() > pcap['fileLength'] or recordCapLen > len(RAW):
        if pcap['fileHandle'].tell() > pcap['fileLength'] or recordCapLen > len(RAW):
            return None,None,None,None
        return RAW,timeval,recordCapLen,recordLen
    else:
        return None,None,None,None

versionMajor,versionMinor,thisZone,sigfigs,snaplen,linktype = 0,0,0,0,0,0
locale_year,locale_month,locale_day,locale_hour,locale_minute,locale_second,temp_second = 0,0,0,0,0,0,0
fileHandle,fileLength = 0,0
readInt16Bytes = 0
readInt32Bytes = 0
readTime = 0
pcapRAW = None

pcapFileHandles = []
pcapIdList = []
pcapBytes = []

totalLength = 0
nextPos = 0
pcapInputList = []

strinfo = re.compile('\D')