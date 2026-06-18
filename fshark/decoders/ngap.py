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

def getByNGAPCode(raw,list):
    if list in (None,[]):
        print('list is empty')
        return

    out = {}
    pos = 3
    len = 0
    if struct.unpack('!B',raw[pos:pos+1])[0] // 128 != 0:
        length_of_raw, pos = struct.unpack('!H',raw[pos:pos+2])[0] - 128*256, pos + 2
    else:
        length_of_raw, pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1

    numberOfItems, pos = struct.unpack('!B',raw[pos:pos+1])[0] * 256 * 256 + struct.unpack('!H',raw[pos+1:pos+3])[0],pos + 3
    
    for i in range(0,numberOfItems):
        try:
            ngapId, pos = struct.unpack('!H',raw[pos:pos+2])[0], pos + 2
        except:
            break
        pos += 1         # skip criticality field  
        if struct.unpack('!B',raw[pos:pos+1])[0] // 128 != 0:
            len,pos = struct.unpack('!H',raw[pos:pos+2])[0] - 128*256, pos + 2
        else:
            len,pos = struct.unpack('!B',raw[pos:pos+1])[0], pos + 1
        if ngapId in list:
            if ngapId == AMF_UE_NGAP_ID:
                amfueid = 0
                for n in raw[pos+1:pos+len]: amfueid = amfueid*256 + n
                out[ngapId] = amfueid
            elif ngapId == RAN_UE_NGAP_ID:
                ranueid = 0
                for n in raw[pos+1:pos+len]:
                    ranueid = ranueid*256 + n
                    # 脱敏导致数据异常，该字段使用6个字节存储，判断超出存储范围时跳出循环
                    if ranueid> 2**48:
                        print('ranueid exception')
                        break
                out[ngapId] = ranueid
            elif ngapId == NAS_PDU:
                nas = raw[pos:pos+len]
                out[ngapId] = [nas]
            elif ngapId == NASC:
                print('need to decode NASC')
                # exit()
                nas = raw[pos:pos+len]
                out[ngapId] = [nas]
            elif ngapId in (PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ,PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ,PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ,):
                pos1 = pos
                num_items,pos1 = struct.unpack('!B',raw[pos1:pos1+1])[0]+1, pos1+1
                out[ngapId] = []
                for n in range(num_items):
                    temp_id,pos1 = struct.unpack('!B',raw[pos1:pos1+1])[0], pos1+1
                    if temp_id == 64:
                        pos1 += 1
                        if struct.unpack('!B',raw[pos1:pos1+1])[0] // 128 != 0:
                            temp_nas_len = struct.unpack('!H',raw[pos1:pos1+2])[0] - 128*256
                            nas = raw[pos1:pos1+temp_nas_len+2]
                            out[ngapId].append(nas)
                        else:
                            temp_nas_len = struct.unpack('!B',raw[pos1:pos1+1])[0]
                            if(temp_nas_len > 0):
                                nas = raw[pos1:pos1+temp_nas_len+1]
                                out[ngapId].append(nas)
                        pos1 += temp_nas_len
            else:
                print('Not decoded ngapId:',ngapId)
                out[ngapId] = ngapId
            list.remove(ngapId)
        pos += len
        if list == []:
            break
    return out

def decodeNAS(xdr,raw):
    xdr_list = []
    xdr['display'] += ', 5G_NAS'
    pos = 0
    nas_length = len(raw)
    pos_end = pos + nas_length
    nextByte = struct.unpack('!B',raw[pos:pos+1])[0]
    if nextByte == 126:                     # Extended protocol discriminator: 5G mobility management messages (126)
        if(struct.unpack("!B",raw[pos+1:pos+2])[0] == 0):               # not encrypted
            pos += 2
            xdr['msgType'],pos = NASDictProc.get(struct.unpack("!B",raw[pos:pos+1])[0],0),pos+1
            print(xdr['display'],xdr['msgType'],NASDictName.get(struct.unpack("!B",raw[pos-1:pos])[0],0))
        # elif(struct.unpack("!B",raw[pos+1:pos+2])[0] in (2,3,4,) ):   # encrypted
        #     pass
        elif(struct.unpack("!B",raw[pos+1:pos+2])[0] in (1,2,3,4,) ):   # encrypted
            pos += 7
            nextByte = struct.unpack('!B',raw[pos:pos+1])[0]
            if nextByte == 126:                     # Extended protocol discriminator: 5G mobility management messages (126)
                if(struct.unpack("!B",raw[pos+1:pos+2])[0] == 0):
                    pos += 2
                    xdr['msgType'],pos = NASDictProc.get(struct.unpack("!B",raw[pos:pos+1])[0],0),pos+1
                    print(xdr['display'],xdr['msgType'],NASDictName.get(struct.unpack("!B",raw[pos-1:pos])[0],0))
                elif(struct.unpack("!B",raw[pos+1:pos+2])[0] in (1,2,3,4,) ):
                    pos += 7
                    print("in NAS decoding, encounter entryption")
                    return
                else:
                    pos += 7
                    print("in NAS decoding, encounter entryption")
                    return
            elif nextByte == 46:                     # Extended protocol discriminator: 5G session management messages (46)
                pos += 3
                xdr['msgType'],pos = NASDictProc.get(struct.unpack("!B",raw[pos:pos+1])[0],0),pos+1
                print(xdr['display'],xdr['msgType'],NASDictName.get(struct.unpack("!B",raw[pos-1:pos])[0],0))
        else:
            pos += 7
            print("in NAS decoding, encounter entryption")
            return
    elif nextByte == 46:                     # Extended protocol discriminator: 5G session management messages (46)
        pos += 3
        xdr['msgType'],pos = NASDictProc.get(struct.unpack("!B",raw[pos:pos+1])[0],0),pos+1
        print(xdr['display'],xdr['msgType'],NASDictName.get(struct.unpack("!B",raw[pos-1:pos])[0],0))


    if xdr['msgType'] == 30129:     # Security Mode Complete
        while pos < pos_end:
            ie_tag,pos = struct.unpack("!B",raw[pos:pos+1])[0], pos+1
            ie_length,pos = struct.unpack("!H",raw[pos:pos+2])[0], pos+2
            if ie_tag == 113:
                inner_xdr1 = xdr.copy()
                nasXDR1_list = decodeNAS(inner_xdr1,raw[pos:pos+ie_length])
                xdr_list = xdr_list + nasXDR1_list
            else:
                pos += ie_length
    elif xdr['msgType'] == 30138:     # UL NAS Transport
        pos += 1
        temp_length,pos = struct.unpack("!H",raw[pos:pos+2])[0], pos+2
        pos_end = pos + temp_length
        inner_xdr = xdr.copy()
        nasXDR_list = decodeNAS(inner_xdr,raw[pos:pos + temp_length])
        xdr_list = xdr_list + nasXDR_list
    elif xdr['msgType'] == 30139:      # DL NAS Transport
        pos += 1
        temp_length,pos = struct.unpack("!H",raw[pos:pos+2])[0], pos+2
        pos_end = pos + temp_length
        inner_xdr = xdr.copy()
        nasXDR_list = decodeNAS(inner_xdr,raw[pos:pos + temp_length])
        xdr_list = xdr_list + nasXDR_list
    elif xdr['msgType'] == 30100:      # Message type: Registration request (0x41)
        pass

    xdr_list.append(xdr)
    return xdr_list

def decodeNGAP(xdr,raw,flush):
    global errorNum,maxSessionID
    xdr['display'] += ', NGAP'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','5'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''
    xdr['msgType'] = ngapDictProc.get(base64.b16encode(raw[0:2]),0)
    print(xdr['display'],xdr['msgType'],ngapDictName.get(base64.b16encode(raw[0:2]),0))
    if(xdr['msgType'] in (30006, 30007, 30024, 30025, 30041, 30047, 30065, 30066, 30067, 30068, 30075, 30076)):
        return

    xdr['5G-guti'] = 0
    xdr['sessionID'] = 0
    IEs = getByNGAPCode(raw,[AMF_UE_NGAP_ID,RAN_UE_NGAP_ID,NAS_PDU,NASC,PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ,PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ,PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ,])
    xdr['amfueid'] = IEs.get(AMF_UE_NGAP_ID,0)
    xdr['ranueid'] = IEs.get(RAN_UE_NGAP_ID,0)

    if xdr['msgType'] in [30000, 30001, 30002, 30003, 30007, 30008, 30010, 30022, 30023, 30024, 30027, 30030, 30031, 30032, 30033, 30034, 30035, 30036, 30039, 30040, 30043, 30048, 30049, 30050, 30051, 30052, 30054, 30056, 30057, 30059, 30060, 30062, 30064, 30066, 30068, 30070, 30071, 30073, 30074, 30077]:
        xdr['dir'] = '0'
        xdr['gNB_ip'] = xdr['sip'][0]
        xdr['AMF_ip'] = xdr['dip'][0]
    else:
        xdr['dir'] = '1'
        xdr['gNB_ip'] = xdr['dip'][0]
        xdr['AMF_ip'] = xdr['sip'][0]
    
    xdrs = [xdr]

    # print(xdr)
    # print(IEs.get(NAS_PDU,[])[0].hex())
    # exit()

    # decode 5G NAS
    nas1 = IEs.get(NAS_PDU,[]) + IEs.get(NASC,[]) + IEs.get(PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ,[]) + IEs.get(PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ,[]) + IEs.get(PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ,[])
    for n in nas1:
        xdr1 = xdr.copy()
        if struct.unpack('!B',n[0:1])[0] // 128 != 0:
            nas_length = struct.unpack('!H',n[0:2])[0] - 128*256
            nasXDR1_list = decodeNAS(xdr1,n[2:2+nas_length])
        else:
            nas_length = struct.unpack('!B',n[0:1])[0]
            nasXDR1_list = decodeNAS(xdr1,n[1:1+nas_length])
        xdrs = xdrs + nasXDR1_list

    if(len(xdrs) == 3):
        temp_xdr = []
        for x in xdrs:
            if(x['msgType'] == 30139 or x['msgType'] == 30138):
                pass
            else:
                temp_xdr.append(x)
        xdrs = temp_xdr
    if xdr['dir'] == '0':
        if xdr['dip'] not in ngapAMFIP and xdr['msgType'] not in [291,292]: ngapAMFIP.append(xdr['dip'])
    else:
        if xdr['sip'] not in ngapAMFIP and xdr['msgType'] not in [291,292]: ngapAMFIP.append(xdr['sip'])

    # pairing messages.
    guti = 0
    stmsi = 0
    imsi = '0'
    for n in xdrs:
        temp_guti = n.get('5G-guti',0)
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
    
    context = (xdr['amfueid'],xdr['gNB_ip'],xdr['ranueid'])
    halfContext = (xdr['gNB_ip'],xdr['ranueid'])
    sessionID1 = ngapSessionID.get(context,0)
    if sessionID1 == 0:
        sessionID1 = ngapHalfSessionID.get(halfContext,0)
        if sessionID1 == 0:
            maxSessionID += 1
            sessionID1 = maxSessionID
        else:
            del ngapHalfSessionID[halfContext]
    
    if xdr['imsi'] != '0': sessionIMSI[sessionID1] = xdr['imsi']
    
    xdr['sessionID'] = sessionID1
    ngapSessionID[(xdr['amfueid'] , xdr['gNB_ip'] , xdr['ranueid'])] = sessionID1
    pathSessionID[xdr['amfueid']] = sessionID1
    if xdr['guti'] != 0:
        gutiSessionID[xdr['guti']] = sessionID1
        pagingSessionID[(xdr['guti'][1],xdr['guti'][2])] = sessionID1

    imsi = sessionIMSI.get(xdr['sessionID'],'0')

    if imsi != '0':  xdr['imsi'] = imsi

    if(xdr['msgType'] == 30053):
        paging_result = paging_dict.get(xdr['stmsi'],None)
        if(paging_result != None):
            del xdr
            return
        else:
            paging_dict[xdr['stmsi']] = True

    for n in xdrs[1:]:
        n['sessionID'] = xdr['sessionID']
        n['imsi'] = xdr['imsi']
        cacheNASXDR(n)
    del xdrs
    cachengapXDR(xdr)
    del xdr

paging_dict = {}

def outputngapXDR(xdr):
    global ngapOutputFile
    if xdr['imsi'] == '0': xdr['imsi'] = str(888885000000000+xdr['sessionID'])
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
        dip = inet_ntoa(xdr['dip'][-1])
    elif len(xdr['sip'][-1]) == 16:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    xdr['interface'] = 'N2'
    if(xdr['imsi'] == '0'): xdr['imsi'] = ''
    if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
    status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr['ranueid']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

    if ngapOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        ngapOutputFileName = os.path.join(status.sdlDirectory, 'NrCP_N2_Msg_'+b+'.tmp')
        ngapOutputFile = open(ngapOutputFileName,'w')
        if ngapOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(ngapOutputFile)
    ngapOutputFile.writelines(string)
    return
def cachengapXDR(xdr):
    sessionID = xdr.get('sessionID',0)
    if sessionID == 0:
        print('Error, xdr without sessionID, packet id=',xdr['id'])
        return
    imsi = xdr.get('imsi','0')
    if imsi != '0':
        for i in range(len(ngapXDR)-1,-1,-1):
            if ngapXDR[i]['sessionID'] == sessionID:
                ngapXDR[i]['imsi'] = imsi
                outputngapXDR(ngapXDR[i])
                ngapXDR.remove(ngapXDR[i])
        outputngapXDR(xdr)
    else:
        ngapXDR.append(xdr)
    cachengapnasCPLatency(xdr)
    return

def flushngapXDR():
    global ngapCPLatency1OutputFile,ngapCPLatency2OutputFile,ngapCPLatency3OutputFile,ngapCPLatency4OutputFile,ngapCPLatency5OutputFile
    for n in ngapXDR:
        imsi = sessionIMSI.get(n['sessionID'],'0')
        if imsi != '0': n['imsi'] = imsi
        outputngapXDR(n)
    ngapXDR.clear()
    for n in pagingList:
        for m in pagingList[n]:
            outputngapXDR(m)
    pagingList.clear()
    return

def outputNASXDR(xdr):
    global nasOutputFile,nasCPLatency1OutputFile,nasCPLatency2OutputFile,nasCPLatency3OutputFile,nasCPLatency4OutputFile,nasCPLatency5OutputFile
    if xdr['msgType'] != 287:
        if xdr['imsi'] == '0': xdr['imsi'] = str(888885000000000+xdr['sessionID'])
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
        ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
        if len(xdr['sip'][-1]) == 4:
            sip = inet_ntoa(xdr['sip'][-1])
            dip = inet_ntoa(xdr['dip'][-1])
        elif len(xdr['sip'][-1]) == 16:
            sip = inet_ntop(AF_INET6, xdr['sip'][-1])
            dip = inet_ntop(AF_INET6, xdr['dip'][-1])
        xdr['interface'] = 'N1'
        if(xdr['imsi'] == '0'): xdr['imsi'] = ''
        if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
        status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'','','',str(xdr['ranueid']),"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

        if nasOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            nasOutputFileName = os.path.join(status.sdlDirectory, 'NrCP_N1_Msg_'+b+'.tmp')
            nasOutputFile = open(nasOutputFileName,'w')
            if nasOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(nasOutputFile)
        nasOutputFile.writelines(string)
    
    # CPLatency
    if xdr['msgType'] in ('30100',):     # request msg
        temp = nasCPLatency.get((xdr['sip'][0],xdr['sport'],xdr['dip'][0],xdr['dport'],xdr['SequenceNumber']),0)               
        if temp != 0:
            temp.append(xdr['ts'])
            return
        else:
            temp = [xdr['ts']]
            nasCPLatency[(xdr['sip'][0],xdr['sport'],xdr['dip'][0],xdr['dport'],xdr['SequenceNumber'])] = temp
            return

    if xdr['msgType'] in ('30101', '30103'):
        temp = nasCPLatency.get((xdr['dip'][0],xdr['dport'],xdr['sip'][0],xdr['sport'],xdr['SequenceNumber']),0)
        if temp != 0:
            xdr['prcType'] = nasPair[xdr['msgType']][1]
            if xdr['Cause'] >= 1 and xdr['Cause'] <= 63:
                xdr['SuccFlag'] = 0
            elif(xdr['msgType'] == '30301'):
                xdr['SuccFlag'] = 0
            else:
                xdr['SuccFlag'] = 2
            xdr['Retrs'] = len(temp)
            if xdr['Retrs'] > 0: xdr['Retrs'] -= 1
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
            del nasCPLatency[(xdr['dip'][0],xdr['dport'],xdr['sip'][0],xdr['sport'],xdr['SequenceNumber'])]
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
    xdr['APN_Id'] = ''
    string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+'|'+str(struct.unpack('!I',xdr['dip'][0][0:4])[0])+'|'+str(struct.unpack('!I',xdr['sip'][0][0:4])[0])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
    if pfcpCPLatencyOutputFile == None:
        a = pcap.printTime(xdr['ts'])
        b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
        pfcpCPLatencyOutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_N4_CPLatency_'+b+'.tmp')
        pfcpCPLatencyOutputFile = open(pfcpCPLatencyOutputFileName,'w')
        if pfcpCPLatencyOutputFile == None:
            exit(-1)
        else:
            status.outputFileList.append(pfcpCPLatencyOutputFile)
    pfcpCPLatencyOutputFile.writelines(string)
    status.file_mode_CPlatency.append(string)

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
    cachengapnasCPLatency(xdr)
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

def cachengapnasCPLatency(xdr):
    global CPlatencyXDR,ngapCPLatency1OutputFile,ngapCPLatency2OutputFile,ngapCPLatency3OutputFile,nasCPLatency1OutputFile,nasCPLatency2OutputFile,nasCPLatency3OutputFile,nasCPLatency4OutputFile,nasCPLatency5OutputFile
    if xdr['msgType'] in (209,206,212,222,222,229,231,241,245,228,249,246,205,202,215,217,220,235,238,240,273,271,288,265,262,257,259,275,291,395,299,297,253):
        temp = ngapnasCPLatency.get((xdr['ranueid'],xdr['amfueid'],xdr['msgType']),0)
        if temp == 0:
            ngapnasCPLatency[(xdr['ranueid'],xdr['amfueid'],xdr['msgType'])] = [xdr]
        else:
            ngapnasCPLatency[(xdr['ranueid'],xdr['amfueid'],xdr['msgType'])].append(xdr)
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
        xdr['eNB_id'] = ''      #ngapnasCPLatency[xdr][0]['eNB_id']
        xdr['xType'] = ''       #ngapnasCPLatency[xdr][0]['xType']
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
                temp = ngapnasCPLatency.get((xdr['ranueid'],xdr['amfueid'],n[0]),0)
                amfueid = 1
                if temp == 0:
                    temp = ngapnasCPLatency.get((xdr['ranueid'],0,n[0]),0)
                    amfueid = 0
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
                    if amfueid == 0:
                        del ngapnasCPLatency[(xdr['ranueid'],0,n[0])]
                    else:
                        del ngapnasCPLatency[(xdr['ranueid'],xdr['amfueid'],n[0])]
                    
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
                    tempxdr['eNB_id'] = ''      #ngapnasCPLatency[xdr][0]['eNB_id']
                    tempxdr['xType'] = ''       #ngapnasCPLatency[xdr][0]['xType']
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
            temp = ngapnasCPLatency.get((xdr['ranueid'],xdr['amfueid'],n[0]),0)
            amfueid = 1
            if temp == 0:
                temp = ngapnasCPLatency.get((xdr['ranueid'],0,n[0]),0)
                amfueid = 0
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
                if amfueid == 0:
                    del ngapnasCPLatency[(xdr['ranueid'],0,n[0])]
                else:
                    del ngapnasCPLatency[(xdr['ranueid'],xdr['amfueid'],n[0])]
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
                tempxdr['eNB_id'] = ''      #ngapnasCPLatency[xdr][0]['eNB_id']
                tempxdr['xType'] = ''       #ngapnasCPLatency[xdr][0]['xType']
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
                nasCPLatency1OutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_NAS_CPLatency1_'+b+'.tmp')
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
                nasCPLatency2OutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_NAS_CPLatency2_'+b+'.tmp')
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
                nasCPLatency3OutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_NAS_CPLatency3_'+b+'.tmp')
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
                nasCPLatency4OutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_NAS_CPLatency4_'+b+'.tmp')
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
                nasCPLatency5OutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_NAS_CPLatency5_'+b+'.tmp')
                nasCPLatency5OutputFile = open(nasCPLatency5OutputFileName,'w')
                if nasCPLatency5OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency5OutputFile)
            nasCPLatency5OutputFile.writelines(string)
        if xdr['prcType'] in (1100,1101,1102,1103,1104,1105,1106,1108,1109,1111,1112,1113,1114,1115,1020):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if ngapCPLatency1OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                ngapCPLatency1OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency1_'+b+'.tmp')
                ngapCPLatency1OutputFile = open(ngapCPLatency1OutputFileName,'w')
                if ngapCPLatency1OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(ngapCPLatency1OutputFile)
            ngapCPLatency1OutputFile.writelines(string)
        elif xdr['prcType'] in (1107,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if ngapCPLatency2OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                ngapCPLatency2OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency2_'+b+'.tmp')
                ngapCPLatency2OutputFile = open(ngapCPLatency2OutputFileName,'w')
                if ngapCPLatency2OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(ngapCPLatency2OutputFile)
            ngapCPLatency2OutputFile.writelines(string)
        elif xdr['prcType'] in (1110,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if ngapCPLatency3OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                ngapCPLatency3OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency3_'+b+'.tmp')
                ngapCPLatency3OutputFile = open(ngapCPLatency3OutputFileName,'w')
                if ngapCPLatency3OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(ngapCPLatency3OutputFile)
            ngapCPLatency3OutputFile.writelines(string)
                
    return

def flushngapnasCPLatency():
    global CPlatencyXDR,nasCPLatency1OutputFile,nasCPLatency2OutputFile,nasCPLatency3OutputFile,nasCPLatency4OutputFile,nasCPLatency5OutputFile
    global ngapCPLatency1OutputFile,ngapCPLatency2OutputFile,ngapCPLatency3OutputFile
    
    for xdr in CPlatencyXDR:
        xdr['imsi'] = sessionIMSI.get(xdr['sessionID'],'0')
    xdrs = CPlatencyXDR
    for xdr in ngapnasCPLatency:
        tempxdr = {}
        tempxdr['sessionID'] = ngapnasCPLatency[xdr][0]['sessionID']
        tempxdr['prcType'] = requestMsg[xdr[2]]
        if xdr[2] == 222:
            if ngapnasCPLatency[xdr][0]['dir'] == 0:
                tempxdr['prcType'] = 1003
            else:
                tempxdr['prcType'] = 1004
        tempxdr['SuccFlag'] = 1
        tempxdr['Retrs'] = len(ngapnasCPLatency[xdr])
        if tempxdr['Retrs'] > 0: tempxdr['Retrs'] -= 1
        ts = ngapnasCPLatency[xdr][0]['ts']
        for m in ngapnasCPLatency[xdr][1:]:
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
        tempxdr['pt_tsn'] = ngapnasCPLatency[xdr][0]['pt_tsn']
        tempxdr['cgi'] = ngapnasCPLatency[xdr][0]['cgi']
        tempxdr['Network'] = ngapnasCPLatency[xdr][0]['Network']
        tempxdr['eNB_id'] = ''      #ngapnasCPLatency[xdr][0]['eNB_id']
        tempxdr['xType'] = ''       #ngapnasCPLatency[xdr][0]['xType']
        tempxdr['eNB_ip'] = ngapnasCPLatency[xdr][0]['eNB_ip']
        tempxdr['MME_ip'] = ngapnasCPLatency[xdr][0]['MME_ip']
        tempxdr['imsi'] = sessionIMSI.get(ngapnasCPLatency[xdr][0]['sessionID'],'0')
        CPlatencyXDR.append(tempxdr)
    ngapnasCPLatency.clear()

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
        xdr['eNB_id'] = ''      #ngapnasCPLatency[xdr][0]['eNB_id']
        xdr['xType'] = ''       #ngapnasCPLatency[xdr][0]['xType']
        xdr['eNB_ip'] = xdr['eNB_ip']
        xdr['MME_ip'] = xdr['MME_ip']
        xdr['sessionID'] = xdr['sessionID']
        xdr['msgType'] = xdr['msgType']
        CPlatencyXDR.append(xdr)
    pagingList.clear()
    
    
    for xdr in CPlatencyXDR:
        if xdr['imsi'] == '0': xdr['imsi'] = str(888885000000000+xdr['sessionID'])
        if xdr['prcType'] in (1000,1001,1002,1003,1004,1006):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'|'+str(xdr['APN_Id'])+'\n'
            if nasCPLatency1OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                nasCPLatency1OutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_NAS_CPLatency1_'+b+'.tmp')
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
                nasCPLatency2OutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_NAS_CPLatency2_'+b+'.tmp')
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
                nasCPLatency3OutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_NAS_CPLatency3_'+b+'.tmp')
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
                nasCPLatency4OutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_NAS_CPLatency4_'+b+'.tmp')
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
                nasCPLatency5OutputFileName = os.path.join(status.sdlDirectory, 'NrRTI_NAS_CPLatency5_'+b+'.tmp')
                nasCPLatency5OutputFile = open(nasCPLatency5OutputFileName,'w')
                if nasCPLatency5OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(nasCPLatency5OutputFile)
            nasCPLatency5OutputFile.writelines(string)
        if xdr['prcType'] in (1100,1101,1102,1103,1104,1105,1106,1108,1109,1111,1112,1113,1114,1115,1020):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if ngapCPLatency1OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                ngapCPLatency1OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency1_'+b+'.tmp')
                ngapCPLatency1OutputFile = open(ngapCPLatency1OutputFileName,'w')
                if ngapCPLatency1OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(ngapCPLatency1OutputFile)
            ngapCPLatency1OutputFile.writelines(string)
        elif xdr['prcType'] in (1107,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if ngapCPLatency2OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                ngapCPLatency2OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency2_'+b+'.tmp')
                ngapCPLatency2OutputFile = open(ngapCPLatency2OutputFileName,'w')
                if ngapCPLatency2OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(ngapCPLatency2OutputFile)
            ngapCPLatency2OutputFile.writelines(string)
        elif xdr['prcType'] in (1110,):
            string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['msisdn'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['tid'])+'|'+str(xdr['cgi'])+'|'+str(xdr['tac'])+'|'+str(xdr['Network'])+'|'+str(xdr['eNB_id'])+'|'+str(xdr['eNB_ip'])+'|'+str(xdr['MME_ip'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['SuccFlag'])+'|'+str(xdr['prcType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Latency'])+'|'+str(xdr['Timeout'])+'|'+str(xdr['Retrs'])+'|'+str(xdr['Cause'])+'\n'
            if ngapCPLatency3OutputFile == None:
                a = pcap.printTime(xdr['ts'])
                b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
                ngapCPLatency3OutputFileName = os.path.join(status.sdlDirectory, 'LteRTI_S1_CPLatency3_'+b+'.tmp')
                ngapCPLatency3OutputFile = open(ngapCPLatency3OutputFileName,'w')
                if ngapCPLatency3OutputFile == None:
                    exit(-1)
                else:
                    status.outputFileList.append(ngapCPLatency3OutputFile)
            ngapCPLatency3OutputFile.writelines(string)
    return

ngapXDR = []
nasXDR = []
errorNum = 0

#status.ranueidDict = {}

CPlatencyXDR = []
ngapnasCPLatency = {}

sessionIMSI = {}

gutiSessionID = {}
ngapSessionID = {}
pagingSessionID = {}
ngapHalfSessionID = {}
pathSessionID = {}
teidSessionID = {}
imsiSessionID = {}

pagingList = {}
pathSwitchReqList = {}
maxSessionID = 0

ngapOutputFile = None
ngapCPLatency1OutputFile = None
ngapCPLatency2OutputFile = None
ngapCPLatency3OutputFile = None


ngapCPLatency = {}
ngapnasCPLatency = {}
nasOutputFile = None
nasCPLatency1OutputFile = None
nasCPLatency2OutputFile = None
nasCPLatency3OutputFile = None
nasCPLatency4OutputFile = None
nasCPLatency5OutputFile = None
nasCPLatency = {}

ngapDictProc = {b'0000': 30000, b'0023': 30001, b'000A': 30002, b'000C': 30003, b'000D': 30004, b'000E': 30005, b'0014': 30006, b'0015': 30007, b'0019': 30008, b'001A': 30009, b'001B': 30010, b'001C': 30011, b'001D': 30012, b'0028': 30013, b'0029': 30014, b'0033': 30015, b'0020': 30016, b'002B': 30017, b'2000': 30018, b'2023': 30019, b'200A': 30020, b'200C': 30021, b'200D': 30022, b'200E': 30023, b'2014': 30024, b'2015': 30025, b'2019': 30026, b'201A': 30027, b'201B': 30028, b'201C': 30029, b'201D': 30030, b'2028': 30031, b'2029': 30032, b'2033': 30033, b'2020': 30034, b'202B': 30035, b'4000': 30036, b'4023': 30037, b'400C': 30038, b'400D': 30039, b'400E': 30040, b'4015': 30041, b'4019': 30042, b'4028': 30043, b'0006': 30044, b'0007': 30045, b'0004': 30046, b'0009': 30047, b'0030': 30048, b'0031': 30049, b'000B': 30050, b'000F': 30051, b'0013': 30052, b'0018': 30053, b'001E': 30054, b'0024': 30055, b'002A': 30056, b'002E': 30057, b'0001': 30058, b'0022': 30059, b'0021': 30060, b'0008': 30061, b'0032': 30062, b'0005': 30063, b'002F': 30064, b'0027': 30065, b'0026': 30066, b'0003': 30067, b'0002': 30068, b'0010': 30069, b'0011': 30070, b'0012': 30071, b'002D': 30072, b'002C': 30073, b'0025': 30074, b'0016': 30075, b'0017': 30076, b'0034': 30077}
ngapDictName = {b'0000': 'AMF CONFIGURATION UPDATE', b'0023': 'RAN CONFIGURATION UPDATE', b'000A': 'HANDOVER CANCEL', b'000C': 'HANDOVER REQUIRED', b'000D': 'HANDOVER REQUEST', b'000E': 'INITIAL CONTEXT SETUP REQUEST', b'0014': 'NG RESET', b'0015': 'NG SETUP REQUEST', b'0019': 'PATH SWITCH REQUEST', b'001A': 'PDU SESSION RESOURCE MODIFY REQUEST', b'001B': 'PDU SESSION RESOURCE MODIFY INDICATION', b'001C': 'PDU SESSION RESOURCE RELEASE COMMAND', b'001D': 'PDU SESSION RESOURCE SETUP REQUEST', b'0028': 'UE CONTEXT MODIFICATION REQUEST', b'0029': 'UE CONTEXT RELEASE COMMAND', b'0033': 'WRITE-REPLACE WARNING REQUEST', b'0020': 'PWS CANCEL REQUEST', b'002B': 'UE RADIO CAPABILITY CHECK REQUEST', b'2000': 'AMF CONFIGURATION UPDATE ACKNOWLEDGE', b'2023': 'RAN CONFIGURATION UPDATE ACKNOWLEDGE', b'200A': 'HANDOVER CANCEL ACKNOWLEDGE', b'200C': 'HANDOVER COMMAND', b'200D': 'HANDOVER REQUEST ACKNOWLEDGE', b'200E': 'INITIAL CONTEXT SETUP RESPONSE', b'2014': 'NG RESET ACKNOWLEDGE', b'2015': 'NG SETUP RESPONSE', b'2019': 'PATH SWITCH REQUEST ACKNOWLEDGE', b'201A': 'PDU SESSION RESOURCE MODIFY RESPONSE', b'201B': 'PDU SESSION RESOURCE MODIFY CONFIRM', b'201C': 'PDU SESSION RESOURCE RELEASE RESPONSE', b'201D': 'PDU SESSION RESOURCE SETUP RESPONSE', b'2028': 'UE CONTEXT MODIFICATION RESPONSE', b'2029': 'UE CONTEXT RELEASE COMPLETE', b'2033': 'WRITE-REPLACE WARNING RESPONSE', b'2020': 'PWS CANCEL RESPONSE', b'202B': 'UE RADIO CAPABILITY CHECK RESPONSE', b'4000': 'AMF CONFIGURATION UPDATE FAILURE', b'4023': 'RAN CONFIGURATION UPDATE FAILURE', b'400C': 'HANDOVER PREPARATION FAILURE', b'400D': 'HANDOVER FAILURE', b'400E': 'INITIAL CONTEXT SETUP FAILURE', b'4015': 'NG SETUP FAILURE', b'4019': 'PATH SWITCH REQUEST FAILURE', b'4028': 'UE CONTEXT MODIFICATION FAILURE', b'0006': 'DOWNLINK RAN CONFIGURATION TRANSFER', b'0007': 'DOWNLINK RAN STATUS TRANSFER', b'0004': 'DOWNLINK NAS TRANSPORT', b'0009': 'ERROR INDICATION', b'0030': 'UPLINK RAN CONFIGURATION TRANSFER', b'0031': 'UPLINK RAN STATUS TRANSFER', b'000B': 'HANDOVER NOTIFY', b'000F': 'INITIAL UE MESSAGE', b'0013': 'NAS NON DELIVERY INDICATION', b'0018': 'PAGING', b'001E': 'PDU SESSION RESOURCE NOTIFY', b'0024': 'REROUTE NAS REQUEST', b'002A': 'UE CONTEXT RELEASE REQUEST', b'002E': 'UPLINK NAS TRANSPORT', b'0001': 'AMF STATUS INDICATION', b'0022': 'PWS RESTART INDICATION', b'0021': 'PWS FAILURE INDICATION', b'0008': 'DOWNLINK UE ASSOCIATED NRPPA TRANSPORT', b'0032': 'UPLINK UE ASSOCIATED NRPPA TRANSPORT', b'0005': 'DOWNLINK NON UE ASSOCIATED NRPPA TRANSPORT', b'002F': 'UPLINK NON UE ASSOCIATED NRPPA TRANSPORT', b'0027': 'TRACE START', b'0026': 'TRACE FAILURE INDICATION', b'0003': 'DEACTIVATE TRACE', b'0002': 'CELL TRAFFIC TRACE', b'0010': 'LOCATION REPORTING CONTROL', b'0011': 'LOCATION REPORTING FAILURE INDICATION', b'0012': 'LOCATION REPORT', b'002D': 'UE TNLA BINDING RELEASE REQUEST', b'002C': 'UE RADIO CAPABILITY INFO INDICATION', b'0025': 'RRC INACTIVE TRANSITION REPORT', b'0016': 'OVERLOAD START', b'0017': 'OVERLOAD STOP', b'0034': 'SECONDARY RAT DATA USAGE REPORT'}

ngapIdDictName = {0:"id-AllowedNSSAI", 1:"id-AMFName", 2:"id-AMFOverloadResponse", 3:"id-AMFSetID", 4:"id-AMF-TNLAssociationFailedToSetupList", 5:"id-AMF-TNLAssociationSetupList", 6:"id-AMF-TNLAssociationToAddList", 7:"id-AMF-TNLAssociationToRemoveList", 8:"id-AMF-TNLAssociationToUpdateList", 9:"id-AMFTrafficLoadReductionIndication", 10:"id-AMF-UE-NGAP-ID", 11:"id-AssistanceDataForPaging", 12:"id-BroadcastCancelledAreaList", 13:"id-BroadcastCompletedAreaList", 14:"id-CancelAllWarningMessages", 15:"id-Cause", 16:"id-CellIDListForRestart", 17:"id-ConcurrentWarningMessageInd", 18:"id-CoreNetworkAssistanceInformationForInactive", 19:"id-CriticalityDiagnostics", 20:"id-DataCodingScheme", 21:"id-DefaultPagingDRX", 22:"id-DirectForwardingPathAvailability", 23:"id-EmergencyAreaIDListForRestart", 24:"id-EmergencyFallbackIndicator", 25:"id-EUTRA-CGI", 26:"id-FiveG-S-TMSI", 27:"id-GlobalRANNodeID", 28:"id-GUAMI", 29:"id-HandoverType", 30:"id-IMSVoiceSupportIndicator", 31:"id-IndexToRFSP", 32:"id-InfoOnRecommendedCellsAndRANNodesForPaging", 33:"id-LocationReportingRequestType", 34:"id-MaskedIMEISV", 35:"id-MessageIdentifier", 36:"id-MobilityRestrictionList", 37:"id-NASC", 38:"id-NAS-PDU", 39:"id-NASSecurityParametersFromNGRAN", 40:"id-NewAMF-UE-NGAP-ID", 41:"id-NewSecurityContextInd", 42:"id-NGAP-Message", 43:"id-NGRAN-CGI", 44:"id-NGRANTraceID", 45:"id-NR-CGI", 46:"id-NRPPa-PDU", 47:"id-NumberOfBroadcastsRequested", 48:"id-OldAMF", 49:"id-OverloadStartNSSAIList", 50:"id-PagingDRX", 51:"id-PagingOrigin", 52:"id-PagingPriority", 53:"id-PDUSessionResourceAdmittedList", 54:"id-PDUSessionResourceFailedToModifyListModRes", 55:"id-PDUSessionResourceFailedToSetupListCxtRes", 56:"id-PDUSessionResourceFailedToSetupListHOAck", 57:"id-PDUSessionResourceFailedToSetupListPSReq", 58:"id-PDUSessionResourceFailedToSetupListSURes", 59:"id-PDUSessionResourceHandoverList", 60:"id-PDUSessionResourceListCxtRelCpl", 61:"id-PDUSessionResourceListHORqd", 62:"id-PDUSessionResourceModifyListModCfm", 63:"id-PDUSessionResourceModifyListModInd", 64:"id-PDUSessionResourceModifyListModReq", 65:"id-PDUSessionResourceModifyListModRes", 66:"id-PDUSessionResourceNotifyList", 67:"id-PDUSessionResourceReleasedListNot", 68:"id-PDUSessionResourceReleasedListPSAck", 69:"id-PDUSessionResourceReleasedListPSFail", 70:"id-PDUSessionResourceReleasedListRelRes", 71:"id-PDUSessionResourceSetupListCxtReq", 72:"id-PDUSessionResourceSetupListCxtRes", 73:"id-PDUSessionResourceSetupListHOReq", 74:"id-PDUSessionResourceSetupListSUReq", 75:"id-PDUSessionResourceSetupListSURes", 76:"id-PDUSessionResourceToBeSwitchedDLList", 77:"id-PDUSessionResourceSwitchedList", 78:"id-PDUSessionResourceToReleaseListHOCmd", 79:"id-PDUSessionResourceToReleaseListRelCmd", 80:"id-PLMNSupportList", 81:"id-PWSFailedCellIDList", 82:"id-RANNodeName", 83:"id-RANPagingPriority", 84:"id-RANStatusTransfer-TransparentContainer", 85:"id-RAN-UE-NGAP-ID", 86:"id-RelativeAMFCapacity", 87:"id-RepetitionPeriod", 88:"id-ResetType", 89:"id-RoutingID", 90:"id-RRCEstablishmentCause", 91:"id-RRCInactiveTransitionReportRequest", 92:"id-RRCState", 93:"id-SecurityContext", 94:"id-SecurityKey", 95:"id-SerialNumber", 96:"id-ServedGUAMIList", 97:"id-SliceSupportList", 98:"id-SONConfigurationTransferDL", 99:"id-SONConfigurationTransferUL", 100:"id-SourceAMF-UE-NGAP-ID", 101:"id-SourceToTarget-TransparentContainer", 102:"id-SupportedTAList", 103:"id-TAIListForPaging", 104:"id-TAIListForRestart", 105:"id-TargetID", 106:"id-TargetToSource-TransparentContainer", 107:"id-TimeToWait", 108:"id-TraceActivation", 109:"id-TraceCollectionEntityIPAddress", 110:"id-UEAggregateMaximumBitRate", 111:"id-UE-associatedLogicalNG-connectionList", 112:"id-UEContextRequest", 114:"id-UE-NGAP-IDs", 115:"id-UEPagingIdentity", 116:"id-UEPresenceInAreaOfInterestList", 117:"id-UERadioCapability", 118:"id-UERadioCapabilityForPaging", 119:"id-UESecurityCapabilities", 120:"id-UnavailableGUAMIList", 121:"id-UserLocationInformation", 122:"id-WarningAreaList", 123:"id-WarningMessageContents", 124:"id-WarningSecurityInfo", 125:"id-WarningType", 126:"id-AdditionalUL-NGU-UP-TNLInformation", 127:"id-DataForwardingNotPossible", 128:"id-DL-NGU-UP-TNLInformation", 129:"id-NetworkInstance", 130:"id-PDUSessionAggregateMaximumBitRate", 131:"id-PDUSessionResourceFailedToModifyListModCfm", 132:"id-PDUSessionResourceFailedToSetupListCxtFail", 133:"id-PDUSessionResourceListCxtRelReq", 134:"id-PDUSessionType", 135:"id-QosFlowAddOrModifyRequestList", 136:"id-QosFlowSetupRequestList", 137:"id-QosFlowToReleaseList", 138:"id-SecurityIndication", 139:"id-UL-NGU-UP-TNLInformation", 140:"id-UL-NGU-UP-TNLModifyList", 141:"id-WarningAreaCoordinates", 142:"id-PDUSessionResourceSecondaryRATUsageList", 143:"id-HandoverFlag", 144:"id-SecondaryRATUsageInformation", 145:"id-PDUSessionResourceReleaseResponseTransfer", 146:"id-RedirectionVoiceFallback", 147:"id-UERetentionInformation", 148:"id-S-NSSAI", 149:"id-PSCellInformation", 150:"id-LastEUTRAN-PLMNIdentity", 151:"id-MaximumIntegrityProtectedDataRate-DL", 152:"id-AdditionalDLForwardingUPTNLInformation", 153:"id-AdditionalDLUPTNLInformationForHOList", 154:"id-AdditionalNGU-UP-TNLInformation", 155:"id-AdditionalDLQosFlowPerTNLInformation", 156:"id-SecurityResult", 157:"id-ENDC-SONConfigurationTransferDL", 158:"id-ENDC-SONConfigurationTransferUL", 159:"id-OldAssociatedQosFlowList-ULendmarkerexpected", 160:"id-CNTypeRestrictionsForEquivalent", 161:"id-CNTypeRestrictionsForServing", 162:"id-NewGUAMI", 163:"id-ULForwarding", 164:"id-ULForwardingUP-TNLInformation", 165:"id-CNAssistedRANTuning", 166:"id-CommonNetworkInstance"}

NASDictProc = {65:30100, 66:30101, 67:30102, 68:30103, 69:30104, 70:30105, 71:30106, 72:30107, 76:30111, 77:30112, 78:30113, 79:30114, 84:30119, 85:30120, 86:30121, 87:30122, 88:30123, 89:30124, 90:30125, 91:30126, 92:30127, 93:30128, 94:30129, 95:30130, 100:30135, 101:30136, 102:30137, 103:30138, 104:30139, 193:30228, 194:30229, 195:30230, 197:30232, 198:30233, 199:30234, 201:30236, 202:30237, 203:30238, 204:30239, 205:30240, 209:30244, 210:30245, 211:30246, 212:30247, 214:30249}
NASDictName = {65:'Registration request', 66:'Registration accept', 67:'Registration complete', 68:'Registration reject', 69:'Deregistration request (UE originating)', 70:'Deregistration accept (UE originating)', 71:'Deregistration request (UE terminated)', 72:'Deregistration accept (UE terminated)', 76:'Service request', 77:'Service reject', 78:'Service accept', 79:'Control plane service request', 84:'Configuration update command', 85:'Configuration update complete', 86:'Authentication request', 87:'Authentication response', 88:'Authentication reject', 89:'Authentication failure', 90:'Authentication result', 91:'Identity request', 92:'Identity response', 93:'Security mode command', 94:'Security mode complete', 95:'Security mode reject', 100:'5GMM status', 101:'Notification', 102:'Notification response', 103:'UL NAS transport', 104:'DL NAS transport', 193:'PDU session establishment request', 194:'PDU session establishment accept', 195:'PDU session establishment reject', 197:'PDU session authentication command', 198:'PDU session authentication complete', 199:'PDU session authentication result', 201:'PDU session modification request', 202:'PDU session modification reject', 203:'PDU session modification command', 204:'PDU session modification complete', 205:'PDU session modification command reject', 209:'PDU session release request', 210:'PDU session release reject', 211:'PDU session release command', 212:'PDU session release complete', 214:'5GSM status'}

# Type    dir  msgNameUS                           msgNameCN          Notes                                                                                 Category    XDR
# 6030    0    Registration request                注册               Registration request(30100)->Registration accept(30101)/Registration accept(30103)     N1         NrRTI_N1_CPLatency

nasPair = {}
nasPair['30101'] = ('30100', '6030', '0')
nasPair['30103'] = ('30100', '6031', '2')

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

ngapAMFIP = []

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

AMF_UE_NGAP_ID = 10
RAN_UE_NGAP_ID = 85
NASC = 37
NAS_PDU = 38
PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ = 71
PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ = 74
PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ = 64