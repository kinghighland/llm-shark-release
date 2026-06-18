import sys
import os
import struct
import base64
import datetime
import time
import binascii
import pcap
import status
from socket import inet_ntop, AF_INET6, inet_ntoa 
from collections import Counter

def decodeBICC(xdr,raw):
    xdr['display'] += ', BICC'
    xdr['Level'] += 1
    if len(raw) < 5:
        print(xdr['display'],'BICC Msg is too small, the length is',len(raw))
        return
    cic,msgType = struct.unpack('!IB',raw[0:5])
    xdr['msgType'] = biccMsg.get(msgType,0)

    xdr['ts1'] = xdr['ts'][0] * 1000000000 + xdr['ts'][1]

    if (xdr['sip'][0],xdr['opc']) not in ipPC:  ipPC.append((xdr['sip'][0],xdr['opc']))
    if (xdr['dip'][0],xdr['dpc']) not in ipPC:  ipPC.append((xdr['dip'][0],xdr['dpc']))

    if msgType == 1:
        print(xdr['display'], 'IAM(Initial Address)')
        pos = struct.unpack('!B',raw[11:12])[0]
        i = struct.unpack('!B',raw[12:13])[0]
        odd = struct.unpack('!B',raw[13:14])[0] >> 7
        isdn = (struct.unpack('!B',raw[14:15])[0] >> 4) & 7
        temp = raw[15:15+i-2]
        calledNumber = ''
        for n in range(len(temp)):
            if n == len(temp)-1:
                if odd == 1:
                    digit = temp[n]&15
                    if digit < 15:  calledNumber += format(digit,'X')
                else:
                    digit = temp[n]&15
                    if digit < 15:  calledNumber += format(digit,'X')
                    digit = temp[n]>>4
                    if digit < 15:  calledNumber += format(digit,'X')
            else:
                digit = temp[n]&15
                if digit < 15:  calledNumber += format(digit,'X')
                digit = temp[n]>>4
                if digit < 15:  calledNumber += format(digit,'X')
        xdr['biccCalledNumber'] = calledNumber
        pos += 12 - 1
        length = len(raw)
        while pos < length-1:
            element = struct.unpack('!B',raw[pos:pos+1])[0]
            elementLength = struct.unpack('!B',raw[pos+1:pos+2])[0]
            if element == 0:
                break
            elif element == 61:
                xdr['biccHopCounter'] = struct.unpack('1B',raw[pos+2:pos+3])[0] & 0x1F
            elif element == 1:
                temp = struct.unpack('!5B',raw[pos+2:pos+7])
                xdr['biccCallID'] = (temp[0]*256+temp[1])*256+temp[2]
                xdr['biccSPC'] = (temp[4] & 0x3F)*256 + temp[3]
            elif element == 40:
                odd = struct.unpack('!B',raw[pos+2:pos+3])[0] >> 7
                temp = struct.unpack('!'+str(elementLength-2)+'B',raw[pos+4:pos+2+elementLength])
                originalCalledNumber = ''
                for n in range(len(temp)):
                    if n == len(temp)-1:
                        if odd == 1:
                            digit = temp[n]&15
                            if digit < 15:  originalCalledNumber += format(digit,'X')
                        else:
                            digit = temp[n]&15
                            if digit < 15:  originalCalledNumber += format(digit,'X')
                            digit = temp[n]>>4
                            if digit < 15:  originalCalledNumber += format(digit,'X')
                    else:
                        digit = temp[n]&15
                        if digit < 14:  originalCalledNumber += format(digit,'X')
                        digit = temp[n]>>4
                        if digit < 14:  originalCalledNumber += format(digit,'X')
                xdr['biccOriginalCalledNumber'] = originalCalledNumber
            pos += elementLength + 2
        if len(status.callFlow) == 0:
            status.callFlow.append(xdr)
        else:
            temp = status.callFlow[len(status.callFlow)-1]
            if temp.get('TSN',0) == xdr['TSN'] and temp.get('streamID',0) == xdr['streamID'] and temp.get('streamSeq',0) == xdr['streamSeq']:
                pass
            else:
                status.callFlow.append(xdr)
        if xdr['biccCalledNumber'][:7] == '1254708':
            if xdr['sip'][0] not in ipGMSC:
                ipGMSC.append(xdr['sip'][0])
                if xdr['sip'][0] in ipMSC:
                    ipMSC.remove(xdr['sip'][0])
            if xdr['opc'] not in pcGMSC:
                pcGMSC.append(xdr['opc'])
                if xdr['opc'] in pcMSC:
                    pcMSC.remove(xdr['opc'])
            if xdr['dip'][0] not in ipMGCF:
                ipMGCF.append(xdr['dip'][0])
                if xdr['dip'][0] in ipMSC:
                    ipMSC.remove(xdr['dip'][0])
            if xdr['dpc'] not in pcMGCF:
                pcMGCF.append(xdr['dpc'])
                if xdr['dpc'] in pcMSC:
                    pcMSC.remove(xdr['dpc'])
        else:
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
    elif msgType == 2:
        print(xdr['display'], 'SAM(Subsequent Address)')
    elif msgType == 3:
        print(xdr['display'], 'INR(Information Request)')
    elif msgType == 4:
        print(xdr['display'], 'INF(Information)')
    elif msgType == 5:
        print(xdr['display'], 'COT(Continuity)')
    elif msgType == 6:
        print(xdr['display'], 'ACM(Address Complete)')
    elif msgType == 7:
        print(xdr['display'], 'CON(Connect)')
    elif msgType == 8:
        print(xdr['display'], 'FOT(Forward Transfer)')
    elif msgType == 9:
        print(xdr['display'], 'ANM(Answer)')
    elif msgType == 12:
        print(xdr['display'], 'REL(Release)')
    elif msgType == 13:
        print(xdr['display'], 'SUS(Suspend)')
    elif msgType == 14:
        print(xdr['display'], 'RES(Resume)')
    elif msgType == 16:
        print(xdr['display'], 'RLC(Release Complete)')
    elif msgType == 31:
        print(xdr['display'], 'FAR(Facility Requesst)')
    elif msgType == 32:
        print(xdr['display'], 'FAA(Facility Accepted)')
    elif msgType == 33:
        print(xdr['display'], 'FRJ(Facility Reject)')
    elif msgType == 44:
        print(xdr['display'], 'CPG(Call Progress)')
    elif msgType == 45:
        print(xdr['display'], 'UUS(User-to-User Information)')
    elif msgType == 47:
        print(xdr['display'], 'CFN(Confusion)')
    elif msgType == 51:
        print(xdr['display'], 'FAC(Facility)')
    elif msgType == 54:
        print(xdr['display'], 'IDR(Identification Request)')
    elif msgType == 55:
        print(xdr['display'], 'IDS(Identification Response)')
    elif msgType == 56:
        print(xdr['display'], 'SGM(Segmentation)')
    elif msgType == 65:
        print(xdr['display'], 'APM(Application Transport)')
    else:
        print(xdr['display'], 'Unknown Message Type',msgType)
    
    updateBICC(xdr)
    cacheBICCXDR(xdr)
    return

def updateBICC(xdr):
    if xdr['dpc'] in pcMGCF or xdr['dip'][0] in ipMGCF:
        xdr['dir'] = '0'
    if xdr['opc'] in pcMGCF or xdr['sip'][0] in ipMGCF:
        xdr['dir'] = '1'

    return

def decodeISUP(xdr, raw):
    xdr['display'] += ', ISUP'
    xdr['Level'] += 1
    if len(raw) < 5:
        print(xdr['display'],'ISUP Msg is too small, the length is',len(raw))
        return
    cic,msgType = struct.unpack('!HB',raw[0:3])
    xdr['msgType'] = biccMsg.get(msgType,0)
    print('msgType',msgType)

    xdr['ts1'] = xdr['ts'][0] * 1000000000 + xdr['ts'][1]

    if (xdr['sip'][0],xdr['opc']) not in ipPC:  ipPC.append((xdr['sip'][0],xdr['opc']))
    if (xdr['dip'][0],xdr['dpc']) not in ipPC:  ipPC.append((xdr['dip'][0],xdr['dpc']))
    
    # 部分逻辑可复用BICC的，如有变化，后续再改
    updateBICC(xdr)
    cacheBICCXDR(xdr)

def decodeM3UA(xdr,raw,flush):
    xdr['display'] += ', M3UA'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','2'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''
    xdr['ip'] = 0
    
    pos = 0
    version,res,msgClass,msgType,msgLength = struct.unpack('!4BI',raw[pos:pos+8])   # M3UA
    if version == 1 or msgClass == 1 or msgType == 1:
        i = pos
        length = i + msgLength
        i += 8
        while i < msgLength-4:
            paraTag, paraLength = struct.unpack('!2H',raw[i:i+4])                   # parameters
            if paraTag == 0:
               break
            elif paraTag == 528:                                                    # Protocol data (SS7 message)
                xdr['opc'],xdr['dpc'],si,ni,mp,sls = struct.unpack('!2I4B',raw[i+4:i+4+12])    # Protocol data
                if si == 3:
                    decodeSCCP(xdr,raw[i+16:i+paraLength])
                    return
                elif si == 5:
                    decodeISUP(xdr,raw[i+16:i+paraLength])
                    return
                elif si == 13:
                    decodeBICC(xdr,raw[i+16:i+paraLength])
                    return
                else:
                    print(xdr['display'],'Not an SCCP message')
                    del xdr,raw
                    return
            i += paraLength
    print(xdr['display'],'version =',version,'msgClass =',msgClass,'msgType =',msgType)
    del xdr,raw
    return

def dst_local_ref_Fixed(raw, pos):
    return raw[pos:pos + 3], pos + 3
def src_local_ref_Fixed(raw, pos):
    return raw[pos:pos + 3], pos + 3
def called_party_addr_Variable(raw, pos):
    len = struct.unpack('B', raw[pos:pos + 1])[0]
    called_addr = {}
    address_indicator = raw[0]
    is_Route_on_GT = ((address_indicator >> 6) & 1) == 1
    global_title_indicator = ((address_indicator >> 2) & 15)
    there_is_ssn = ((address_indicator >> 1) & 1) == 1
    there_is_gt = (address_indicator & 1) == 1
    pos = 0
    if there_is_ssn:
        ssn = raw[pos]
        pos += 1
        called_addr['there_is_ssn'] = True
        called_addr['ssn'] = ssn

    return raw[pos+1:pos + 1 + len], pos + 1 + len
def calling_party_addr_Variable(raw, pos):
    len = struct.unpack('B', raw[pos:pos + 1])[0]
    return raw[pos+1:pos + 1 + len], pos + 1 + len
def protocol_class_Fixed(raw, pos):
    return raw[pos:pos+1], pos + 1
def seg_reassambling_Fixed(raw, pos):
    return raw[pos:pos+1], pos + 1
def recv_seq_num_Fixed(raw, pos):
    return raw[pos:pos+1], pos + 1
def seq_segmenting_Fixed(raw, pos):
    return raw[pos:pos+2], pos + 2
def credit_Fixed(raw, pos):
    return raw[pos, pos + 1], pos + 1
def release_cause_Fixed(raw, pos):
    return raw[pos: pos + 1], pos + 1
def return_cause_Fixed(raw, pos):
    return raw[pos: pos + 1], pos + 1
def reset_cause_Fixed(raw, pos):
    return raw[pos: pos + 1], pos + 1
def error_cause_Fixed(raw, pos):
    return raw[pos: pos + 1], pos + 1
def refusal_cause_Fixed(raw, pos):
    return raw[pos: pos + 1], pos + 1
def data_Variable(raw, pos):
    len = struct.unpack('B', raw[pos:pos + 1])[0]
    return raw[pos+1:pos + 1 + len], pos + 1 + len
def segment_Fixed(raw, pos):
    return raw[pos: pos + 4], pos + 4
def hop_counter_Fixed(raw, pos):
    return raw[pos: pos + 1], pos + 1
def importance_Fixed(raw, pos):
    return raw[pos: pos + 1], pos + 1
def importance_Fixed(raw, pos):
    len = struct.unpack('!H', raw[pos:pos + 2])[0]
    return raw[pos+1:pos + 2 + len], pos + 2 + len

def decodeSCCP(xdr,raw):
    xdr['display'] += ', SCCP'
    pos = 0
    sccpType = struct.unpack('!B',raw[pos:pos+1])[0]
    pos += 1
    if sccpType == 1:
        xdr['display'] += ', Connection Request'
        # Fixed parameters
        src_local_ref, pos = src_local_ref_Fixed(raw,pos)
        protocol_class, pos = protocol_class_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = [called_party_addr_Variable]
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]
        [(called_party_addr, _)] = [(x[0](raw, x[1]+pos)) for x in zip(variable_parameter_list,variable_list)]

        # Optional parameters
        lenth_of_raw = len(raw)
        pos += len(variable_parameter_list) + optional_pointer
        while pos < lenth_of_raw:
            parameter = struct.unpack('B', raw[pos: pos + 1])[0]
            if(parameter == 0):
                break
            else:
                parameter_length = struct.unpack('B', raw[pos + 1: pos + 2])[0]
                if(parameter == 15):
                    decodeSCCPData(xdr,raw[pos+2: pos+2+parameter_length])
            pos += 2 + parameter_length
    elif sccpType == 2:
        # print(xdr['display'],' Connection confirm')
        xdr['display'] += ', Connection confirm'
        # Fixed parameters
        dst_local_ref, pos = dst_local_ref_Fixed(raw,pos)
        src_local_ref, pos = src_local_ref_Fixed(raw,pos)
        protocol_class, pos = protocol_class_Fixed(raw,pos)
        # Variable parameters
        variable_parameter_list = []
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]

        # Optional parameters
        lenth_of_raw = len(raw)
        pos += len(variable_parameter_list) + optional_pointer
        while pos < lenth_of_raw:
            parameter = struct.unpack('B', raw[pos: pos + 1])[0]
            if(parameter == 0):
                break
            else:
                parameter_length = struct.unpack('B', raw[pos + 1: pos + 2])[0]
                if(parameter == 15):
                    decodeSCCPData(xdr,raw[pos+2: pos+2+parameter_length])
            pos += 2 + parameter_length
    elif sccpType == 3:
        xdr['display'] += ', Connection refused'
        # Fixed parameters
        dst_local_ref, pos = dst_local_ref_Fixed(raw,pos)
        refusal_cause, pos = refusal_cause_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = []
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]

        # Optional parameters
        lenth_of_raw = len(raw)
        pos += len(variable_parameter_list) + optional_pointer
        while pos < lenth_of_raw:
            parameter = struct.unpack('B', raw[pos: pos + 1])[0]
            if(parameter == 0):
                break
            else:
                parameter_length = struct.unpack('B', raw[pos + 1: pos + 2])[0]
                if(parameter == 15):
                    decodeSCCPData(xdr,raw[pos+2: pos+2+parameter_length])
            pos += 2 + parameter_length
    elif sccpType == 4:
        xdr['display'] += ', Release'
        # Fixed parameters
        dst_local_ref, pos = dst_local_ref_Fixed(raw,pos)
        src_local_ref, pos = src_local_ref_Fixed(raw,pos)
        release_cause, pos = release_cause_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = []
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]

        # Optional parameters
        lenth_of_raw = len(raw)
        pos += len(variable_parameter_list) + optional_pointer
        while pos < lenth_of_raw:
            parameter = struct.unpack('B', raw[pos: pos + 1])[0]
            if(parameter == 0):
                break
            else:
                parameter_length = struct.unpack('B', raw[pos + 1: pos + 2])[0]
                if(parameter == 15):
                    decodeSCCPData(xdr,raw[pos+2: pos+2+parameter_length])
            pos += 2 + parameter_length
    elif sccpType == 5:
        print(xdr['display'],' Release complete not decoded')
        del xdr,raw
        return
    elif sccpType == 6:
        xdr['display'] += ', Data form 1'
        # Fixed parameters
        dst_local_ref, pos = dst_local_ref_Fixed(raw,pos)
        seg_reassambling, pos = seg_reassambling_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = [data_Variable]
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]
        [(RawData, _)] = [(x[0](raw, x[1]+pos)) for x in zip(variable_parameter_list,variable_list)]
        decodeSCCPData(xdr,RawData)
    elif sccpType == 7:
        xdr['display'] += ', Data form 2'
        # Fixed parameters
        dst_local_ref, pos = dst_local_ref_Fixed(raw,pos)
        seq_segmenting, pos = seq_segmenting_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = [data_Variable]
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]
        [(RawData, _)] = [(x[0](raw, x[1]+pos)) for x in zip(variable_parameter_list,variable_list)]
        decodeSCCPData(xdr,RawData)
    elif sccpType == 8:
        print(xdr['display'],' Data acknowledgement not decoded')
        del xdr,raw
        return
    elif sccpType == 9:
        xdr['display'] += ' Unitdata (UDT)'
        # Fixed parameters
        protocol_class, pos = protocol_class_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = [called_party_addr_Variable,calling_party_addr_Variable,data_Variable]
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]

        [(calling_party_addr, _),(called_party_addr, _),(RawData, _)] = [(x[0](raw, x[1]+pos)) for x in zip(variable_parameter_list,variable_list)]
        decodeSCCPData(xdr,RawData)
    elif sccpType == 10:
        xdr['display'] += ' Unitdata service (UDTS)'
        # Fixed parameters
        return_cause, pos = return_cause_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = [called_party_addr_Variable,calling_party_addr_Variable,data_Variable]
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]

        [(calling_party_addr, _),(called_party_addr, _),(RawData, _)] = [(x[0](raw, x[1]+pos)) for x in zip(variable_parameter_list,variable_list)]
        decodeSCCPData(xdr,RawData)
    elif sccpType == 11:
        xdr['display'] += ' Expedited data (ED)'
        # Fixed parameters
        dst_local_ref, pos = dst_local_ref_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = [data_Variable]
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]

        [(RawData, _)] = [(x[0](raw, x[1]+pos)) for x in zip(variable_parameter_list,variable_list)]
        decodeSCCPData(xdr,RawData)
    elif sccpType == 12:
        print(xdr['display'],' Expedited data acknowledgement not decoded')
        del xdr,raw
        return
    elif sccpType == 13:
        print(xdr['display'],' Reset request not decoded')
        del xdr,raw
        return
    elif sccpType == 14:
        print(xdr['display'],' Reset confirmation not decoded')
        del xdr,raw
        return
    elif sccpType == 15:
        print(xdr['display'],' Protocol data unit error not decoded')
        pass
    elif sccpType == 16:
        print(xdr['display'],' Inactivity test not decoded')
        del xdr,raw
        return
    elif sccpType == 17:
        xdr['display'] += ', Extended unitdata (XUDT)'

        # Fixed parameters
        protocol_class, pos = protocol_class_Fixed(raw,pos)
        hop_counter, pos = hop_counter_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = [called_party_addr_Variable,calling_party_addr_Variable,data_Variable]
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]

        [(calling_party_addr, _),(called_party_addr, _),(RawData, _)] = [(x[0](raw, x[1]+pos)) for x in zip(variable_parameter_list,variable_list)]
        decodeSCCPData(xdr,RawData)
    elif sccpType == 18:
        xdr['display'] += ', Extended unitdata service(XUDTS)'

        # Fixed parameters
        return_cause, pos = return_cause_Fixed(raw,pos)
        hop_counter, pos = hop_counter_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = [called_party_addr_Variable,calling_party_addr_Variable,data_Variable]
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]

        [(calling_party_addr, _),(called_party_addr, _),(RawData, _)] = [(x[0](raw, x[1]+pos)) for x in zip(variable_parameter_list,variable_list)]
        decodeSCCPData(xdr,RawData)
    elif sccpType == 19:
        xdr['display'] += ', Long unitdata (LUDT)'

        # Fixed parameters
        protocol_class, pos = protocol_class_Fixed(raw,pos)
        hop_counter, pos = hop_counter_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = [called_party_addr_Variable,calling_party_addr_Variable,data_Variable]
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]

        [(calling_party_addr, _),(called_party_addr, _),(RawData, _)] = [(x[0](raw, x[1]+pos)) for x in zip(variable_parameter_list,variable_list)]
        decodeSCCPData(xdr,RawData)
    elif sccpType == 20:
        xdr['display'] += ', Long unitdata service (LUDTS)'
        # Fixed parameters
        return_cause, pos = return_cause_Fixed(raw,pos)
        hop_counter, pos = hop_counter_Fixed(raw,pos)

        # Variable parameters
        variable_parameter_list = [called_party_addr_Variable,calling_party_addr_Variable,data_Variable]
        variable_list = [x[0]+x[1] for x in enumerate(raw[pos: pos + len(variable_parameter_list)])]
        optional_pointer = raw[pos+len(variable_parameter_list)]

        [(calling_party_addr, _),(called_party_addr, _),(RawData, _)] = [(x[0](raw, x[1]+pos)) for x in zip(variable_parameter_list,variable_list)]
        decodeSCCPData(xdr,RawData)
    else:
        print(xdr['display'],' Unknown sccpType',sccpType)
    return

def decodeSCCPData(xdr,raw):
    if len(raw) >= 7:
        spare1,msgType,spare2,length = struct.unpack('!4B',raw[0:4])
        if 0<= msgType <= 46:
            openLength = 1
            if length // 128 != 0:
                length = struct.unpack('!H',raw[3:5])[0] - 32768
                openLength = 2
            if length == len(raw) - 3 - openLength:
                nextByte = struct.unpack('!H',raw[4+openLength:6+openLength])[0]
                if nextByte < 256:
                    decodeRANAP(xdr,raw)
                    return
    Byte1,Byte2,Byte3 = struct.unpack('!3B',raw[0:3])
    if Byte1 == 0 and Byte2 == len(raw) - 2:
        if Byte2 == 0x40 and Byte3 != 0x01:
            decodeRANAP(xdr,raw)
        else:
            decodeBSSAP(xdr,raw)
    elif Byte1 == 1 and Byte3 == len(raw) - 3:
        decodeBSSAP(xdr,raw)
    return

def getByRANAPCode(raw,list):
    if list in (None,[]):
        print('list is empty')
        return

    out = {}
    pos = 3
    len1 = 0
    if struct.unpack('!B',raw[pos:pos+1])[0] // 128 != 0:
        pos += 3
    else:
        pos += 2
    numberOfItems,pos = struct.unpack('!H',raw[pos:pos+2])[0], pos+2
    for i in range(0,numberOfItems):
        ranapId = struct.unpack('!H',raw[pos:pos+2])[0]
        pos += 3
        if struct.unpack('!B',raw[pos:pos+1])[0] // 128 != 0:
            len1 = struct.unpack('!H',raw[pos:pos+2])[0] - 128*256
            pos += 2
        else:
            len1 = struct.unpack('!B',raw[pos:pos+1])[0]
            pos += 1
        if ranapId in list:
            if ranapId == 1016:            # id-E-RABToBeSetupListBearerSUReq
                pass
            elif ranapId == 16:                                          # NAS
                if struct.unpack('!B',raw[pos:pos+1])[0] // 128 != 0:
                    lenNAS = struct.unpack('!H',raw[pos:pos+2])[0] - 128*256
                    pos += 2
                else:
                    lenNAS = struct.unpack('!B',raw[pos:pos+1])[0]
                    pos += 1
                nas = raw[pos:pos+lenNAS]
                out[ranapId] = nas
            list.remove(ranapId)
        if list == []:
            break
        pos += len1
    return out

def decodeRANAP(xdr,raw):
    xdr['display'] += ', RANAP'
    xdr['Network'] = 3
    if len(raw) < 7:
        print('Length of RANAP is less than 7 bytes.')
        del xdr,raw
        return
    msgType,spare2,length = struct.unpack('!H2B',raw[0:4])
    openLength = 1
    if length // 128 != 0:
        length = struct.unpack('!H',raw[3:5])[0] - 32768
        openLength = 2
    msgType = msgType & 0x7FFF
    xdr['msgType'] = ranap.get(msgType,0)
    pos = 3
    if msgType == 0x0001:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS IU RELEASE COMMAND')
            xdr['msgType'] = 700
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS IU RELEASE COMMAND')
            xdr['msgType'] = 134
        else:
            print(xdr['display'], 'UnKnown IU RELEASE COMMAND')
            xdr['msgTypeOriginal'] = 0x0001
            xdr['msgType'] = 0
    elif msgType == 0x0002:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RELOCATION REQUIRED')
            xdr['msgType'] = 701
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RELOCATION REQUIRED')
            xdr['msgType'] = 154
        else:
            print(xdr['display'], 'UnKnown RELOCATION REQUIRED')
            xdr['msgTypeOriginal'] = 0x0002
            xdr['msgType'] = 0
    elif msgType == 0x0003:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS RELOCATION REQUEST')
            xdr['msgType'] = 702
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS RELOCATION REQUEST')
            xdr['msgType'] = 149
        else:
            print(xdr['display'], 'UnKnown RELOCATION REQUEST')
            xdr['msgTypeOriginal'] = 0x0003
            xdr['msgType'] = 0
    elif msgType == 0x0004:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RELOCATION CANCEL')
            xdr['msgType'] = 703
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RELOCATION CANCEL')
            xdr['msgType'] = 145
        else:
            print(xdr['display'], 'UnKnown RELOCATION CANCEL')
            xdr['msgTypeOriginal'] = 0x0004
            xdr['msgType'] = 0
    elif msgType == 0x0005:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS SRNS CONTEXT REQUEST')
            xdr['msgType'] = 704
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS SRNS CONTEXT REQUEST')
            xdr['msgType'] = 173
        else:
            print(xdr['display'], 'UnKnown SRNS CONTEXT REQUEST')
            xdr['msgTypeOriginal'] = 0x0005
            xdr['msgType'] = 0
    elif msgType == 0x0006:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS SECURITY MODE COMMAND')
            xdr['msgType'] = 705
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS SECURITY MODE COMMAND')
            xdr['msgType'] = 155
        else:
            print(xdr['display'], 'UnKnown SECURITY MODE COMMAND')
            xdr['msgTypeOriginal'] = 0x0006
            xdr['msgType'] = 0
    elif msgType == 0x0007:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS DATA VOLUME REPORT REQUEST')
            xdr['msgType'] = 706
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS DATA VOLUME REPORT REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown DATA VOLUME REPORT REQUEST')
            xdr['msgTypeOriginal'] = 0x0007
            xdr['msgType'] = 0
    elif msgType == 0x0009:
        xdr['dir'] = '0'
        if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
            xdr['dir'] = '1'
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS RESET')
            xdr['msgType'] = 707
            xdr['dir'] = '1'
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS RESET')
            # xdr['msgType'] =
            xdr['dir'] = '1'
            return
        elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RESET')
            xdr['msgType'] = 707
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RESET')
            # xdr['msgType'] =
            xdr['dir'] = '0'
            return
        else:
            print(xdr['display'], 'UnKnown RESET')
            xdr['msgTypeOriginal'] = 0x0009
            xdr['msgType'] = 0
    elif msgType == 0x001B:
        xdr['dir'] = '0'
        if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
            xdr['dir'] = '1'
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS RESET RESOURCE')
            xdr['msgType'] = 708
            xdr['dir'] = '1'
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS RESET RESOURCE')
            # xdr['msgType'] =
            xdr['dir'] = '1'
            return
        elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RESET RESOURCE')
            xdr['msgType'] = 708
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RESET RESOURCE')
            # xdr['msgType'] =
            return
            xdr['dir'] = '0'
        else:
            print(xdr['display'], 'UnKnown RESET RESOURCE')
            xdr['msgTypeOriginal'] = 0x001B
            xdr['msgType'] = 0
    elif msgType == 0x001E:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS LOCATION RELATED DATA REQUEST')
            xdr['msgType'] = 709
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS LOCATION RELATED DATA REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown LOCATION RELATED DATA REQUEST')
            xdr['msgTypeOriginal'] = 0x001E
            xdr['msgType'] = 0
    elif msgType == 0x001F:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS INFORMATION TRANSFER INDICATION')
            xdr['msgType'] = 710
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS INFORMATION TRANSFER INDICATION')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown INFORMATION TRANSFER INDICATION')
            xdr['msgTypeOriginal'] = 0x001F
            xdr['msgType'] = 0
    elif msgType == 0x0021:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS UPLINK INFORMATION EXCHANGE REQUEST')
            xdr['msgType'] = 711
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS UPLINK INFORMATION EXCHANGE REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown UPLINK INFORMATION EXCHANGE REQUEST')
            xdr['msgTypeOriginal'] = 0x0021
            xdr['msgType'] = 0
    elif msgType == 0x0023:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS SESSION START')
            xdr['msgType'] = 712
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS SESSION START')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS SESSION START')
            xdr['msgTypeOriginal'] = 0x0023
            xdr['msgType'] = 0
    elif msgType == 0x0024:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS SESSION UPDATE')
            xdr['msgType'] = 713
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS SESSION UPDATE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS SESSION UPDATE')
            xdr['msgTypeOriginal'] = 0x0024
            xdr['msgType'] = 0
    elif msgType == 0x0025:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS SESSION STOP REQUEST')
            xdr['msgType'] = 714
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS SESSION STOP REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS SESSION STOP REQUEST')
            xdr['msgTypeOriginal'] = 0x0025
            xdr['msgType'] = 0
    elif msgType == 0x0026:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS UE LINKING REQUEST')
            xdr['msgType'] = 715
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS UE LINKING REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS UE LINKING REQUEST')
            xdr['msgTypeOriginal'] = 0x0026
            xdr['msgType'] = 0
    elif msgType == 0x0027:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS REGISTRATION REQUEST')
            xdr['msgType'] = 716
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS REGISTRATION REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS REGISTRATION REQUEST')
            xdr['msgTypeOriginal'] = 0x0027
            xdr['msgType'] = 0
    elif msgType == 0x0028:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS CN DE-REGISTRATION REQUEST')
            xdr['msgType'] = 717
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS CN DE-REGISTRATION REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS CN DE-REGISTRATION REQUEST')
            xdr['msgTypeOriginal'] = 0x0028
            xdr['msgType'] = 0
    elif msgType == 0x002A:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS RAB RELEASE REQUEST')
            xdr['msgType'] = 718
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS RAB RELEASE REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS RAB RELEASE REQUEST')
            xdr['msgTypeOriginal'] = 0x002A
            xdr['msgType'] = 0
    elif msgType == 0x002B:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS ENHANCED RELOCATION COMPLETE REQUEST')
            xdr['msgType'] = 719
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS ENHANCED RELOCATION COMPLETE REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown ENHANCED RELOCATION COMPLETE REQUEST')
            xdr['msgTypeOriginal'] = 0x002B
            xdr['msgType'] = 0
    elif msgType == 0x002D:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RANAP ENHANCED RELOCATION INFORMATION REQUEST')
            xdr['msgType'] = 720
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RANAP ENHANCED RELOCATION INFORMATION REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown RANAP ENHANCED RELOCATION INFORMATION REQUEST')
            xdr['msgTypeOriginal'] = 0x002D
            xdr['msgType'] = 0
    elif msgType == 0x002E:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS SRVCC CS KEYS REQUEST')
            xdr['msgType'] = 721
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS SRVCC CS KEYS REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown SRVCC CS KEYS REQUEST')
            xdr['msgTypeOriginal'] = 0x002E
            xdr['msgType'] = 0
    elif msgType == 0x001D:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RAB MODIFY REQUEST')
            xdr['msgType'] = 722
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RAB MODIFY REQUEST')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown RAB MODIFY REQUEST')
            xdr['msgTypeOriginal'] = 0x001D
            xdr['msgType'] = 0
    elif msgType == 0x000A:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RAB RELEASE REQUEST')
            xdr['msgType'] = 723
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RAB RELEASE REQUEST')
            xdr['msgType'] = 144
        else:
            print(xdr['display'], 'UnKnown RAB RELEASE REQUEST')
            xdr['msgTypeOriginal'] = 0x000A
            xdr['msgType'] = 0
    elif msgType == 0x000B:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS IU RELEASE REQUEST')
            xdr['msgType'] = 724
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS IU RELEASE REQUEST')
            xdr['msgType'] = 136
        else:
            print(xdr['display'], 'UnKnown IU RELEASE REQUEST')
            xdr['msgTypeOriginal'] = 0x000B
            xdr['msgType'] = 0
    elif msgType == 0x000C:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RELOCATION DETECT')
            xdr['msgType'] = 725
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RELOCATION DETECT')
            xdr['msgType'] = 151
        else:
            print(xdr['display'], 'UnKnown RELOCATION DETECT')
            xdr['msgTypeOriginal'] = 0x000C
            xdr['msgType'] = 0
    elif msgType == 0x000D:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RELOCATION COMPLETE')
            xdr['msgType'] = 726
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RELOCATION COMPLETE')
            xdr['msgType'] = 148
        else:
            print(xdr['display'], 'UnKnown RELOCATION COMPLETE')
            xdr['msgTypeOriginal'] = 0x000D
            xdr['msgType'] = 0
    elif msgType == 0x001C:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RANAP RELOCATION INFORMATION')
            xdr['msgType'] = 727
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RANAP RELOCATION INFORMATION')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown RANAP RELOCATION INFORMATION')
            xdr['msgTypeOriginal'] = 0x001C
            xdr['msgType'] = 0
    elif msgType == 0x0017:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS SRNS DATA FORWARD COMMAND')
            xdr['msgType'] = 728
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS SRNS DATA FORWARD COMMAND')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown SRNS DATA FORWARD COMMAND')
            xdr['msgTypeOriginal'] = 0x0017
            xdr['msgType'] = 0
    elif msgType == 0x0018:
        xdr['dir'] = '0'
        if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
            xdr['dir'] = '1'
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS FORWARD SRNS CONTEXT')
            xdr['msgType'] = 730
            xdr['dir'] = '1'
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS FORWARD SRNS CONTEXT')
            xdr['msgType'] = 175
            xdr['dir'] = '1'
        elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS FORWARD SRNS CONTEXT')
            xdr['msgType'] = 729
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS FORWARD SRNS CONTEXT')
            xdr['msgType'] = 175
            xdr['dir'] = '0'
        else:
            print(xdr['display'], 'UnKnown FORWARD SRNS CONTEXT')
            xdr['msgTypeOriginal'] = 0x0018
            xdr['msgType'] = 0
    elif msgType == 0x000E:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS PAGING')
            xdr['msgType'] = 731
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS PAGING')
            xdr['msgType'] = 131
        else:
            print(xdr['display'], 'UnKnown PAGING')
            xdr['msgTypeOriginal'] = 0x000E
            xdr['msgType'] = 0
    elif msgType == 0x000F:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS COMMON ID')
            xdr['msgType'] = 732
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS COMMON ID')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown COMMON ID')
            xdr['msgTypeOriginal'] = 0x000F
            xdr['msgType'] = 0
    elif msgType == 0x0010:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS CN INVOKE TRACE')
            xdr['msgType'] = 733
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS CN INVOKE TRACE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown CN INVOKE TRACE')
            xdr['msgTypeOriginal'] = 0x0010
            xdr['msgType'] = 0
    elif msgType == 0x001A:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS CN DEACTIVATE TRACE')
            xdr['msgType'] = 734
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS CN DEACTIVATE TRACE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown CN DEACTIVATE TRACE')
            xdr['msgTypeOriginal'] = 0x001A
            xdr['msgType'] = 0
    elif msgType == 0x0011:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS LOCATION REPORTING CONTROL')
            xdr['msgType'] = 735
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS LOCATION REPORTING CONTROL')
            xdr['msgType'] = 138
        else:
            print(xdr['display'], 'UnKnown LOCATION REPORTING CONTROL')
            xdr['msgTypeOriginal'] = 0x0011
            xdr['msgType'] = 0
    elif msgType == 0x0012:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS LOCATION REPORT')
            xdr['msgType'] = 736
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS LOCATION REPORT')
            xdr['msgType'] = 137
        else:
            print(xdr['display'], 'UnKnown LOCATION REPORT')
            xdr['msgTypeOriginal'] = 0x0012
            xdr['msgType'] = 0
    elif msgType == 0x0013:
        xdr['dir'] = '0'
        IEs = getByRANAPCode(raw,[16])
        nas = IEs.get(16,0)
        if nas != 0:
            tempxdr = xdr.copy()
            decodeL3Msg(tempxdr,nas)
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS INITIAL UE MESSAGE')
            xdr['msgType'] = 737
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS INITIAL UE MESSAGE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown INITIAL UE MESSAGE')
            xdr['msgTypeOriginal'] = 0x0013
            xdr['msgType'] = 0
    elif msgType == 0x0014:
        xdr['dir'] = '0'
        IEs = getByRANAPCode(raw,[16])
        nas = IEs.get(16,0)
        if nas != 0:
            tempxdr = xdr.copy()
            decodeL3Msg(tempxdr,nas)
        if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
            xdr['dir'] = '1'
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS DIRECT TRANSFER')
            xdr['msgType'] = 738
            xdr['dir'] = '1'
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS DIRECT TRANSFER')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '1'
        elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS DIRECT TRANSFER')
            xdr['msgType'] = 738
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS DIRECT TRANSFER')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '0'
        else:
            print(xdr['display'], 'UnKnown DIRECT TRANSFER')
            xdr['msgTypeOriginal'] = 0x0014
            xdr['msgType'] = 0
    elif msgType == 0x0015:
        xdr['dir'] = '0'
        if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
            xdr['dir'] = '1'
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS OVERLOAD')
            xdr['msgType'] = 739
            xdr['dir'] = '1'
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS OVERLOAD')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '1'
        elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS OVERLOAD')
            xdr['msgType'] = 739
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS OVERLOAD')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '0'
        else:
            print(xdr['display'], 'UnKnown OVERLOAD')
            xdr['msgTypeOriginal'] = 0x0015
            xdr['msgType'] = 0
    elif msgType == 0x0016:
        xdr['dir'] = '0'
        if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
            xdr['dir'] = '1'
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS ERROR INDICATION')
            xdr['msgType'] = 740
            xdr['dir'] = '1'
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS ERROR INDICATION')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '1'
        elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS ERROR INDICATION')
            xdr['msgType'] = 740
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS ERROR INDICATION')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '0'
        else:
            print(xdr['display'], 'UnKnown ERROR INDICATION')
            xdr['msgTypeOriginal'] = 0x0016
            xdr['msgType'] = 0
    elif msgType == 0x0020:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS UE SPECIFIC INFORMATION INDICATION')
            xdr['msgType'] = 741
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS UE SPECIFIC INFORMATION INDICATION')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown UE SPECIFIC INFORMATION INDICATION')
            xdr['msgTypeOriginal'] = 0x0020
            xdr['msgType'] = 0
    elif msgType == 0x0022:
        xdr['dir'] = '0'
        if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
            xdr['dir'] = '1'
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS DIRECT INFORMATION TRANSFER')
            xdr['msgType'] = 742
            xdr['dir'] = '1'
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS DIRECT INFORMATION TRANSFER')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '1'
        elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS DIRECT INFORMATION TRANSFER')
            xdr['msgType'] = 742
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS DIRECT INFORMATION TRANSFER')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '0'
        else:
            print(xdr['display'], 'UnKnown DIRECT INFORMATION TRANSFER')
            xdr['msgTypeOriginal'] = 0x0022
            xdr['msgType'] = 0
    elif msgType == 0x0029:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS RAB ESTABLISHMENT INDICATION')
            xdr['msgType'] = 743
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS RAB ESTABLISHMENT INDICATION')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS RAB ESTABLISHMENT INDICATION')
            xdr['msgTypeOriginal'] = 0x0029
            xdr['msgType'] = 0
    elif msgType == 0x002C:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS ENHANCED RELOCATION COMPLETE CONFIRM')
            xdr['msgType'] = 744
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS ENHANCED RELOCATION COMPLETE CONFIRM')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown ENHANCED RELOCATION COMPLETE CONFIRM')
            xdr['msgTypeOriginal'] = 0x002C
            xdr['msgType'] = 0
    elif msgType == 0x0000:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS RAB ASSIGNMENT REQUEST')
            xdr['msgType'] = 745
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS RAB ASSIGNMENT REQUEST')
            xdr['msgType'] = 142
        else:
            print(xdr['display'], 'UnKnown RAB ASSIGNMENT REQUEST')
            xdr['msgTypeOriginal'] = 0x0000
            xdr['msgType'] = 0
    elif msgType == 0x2001:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS IU RELEASE COMPLETE')
            xdr['msgType'] = 746
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS IU RELEASE COMPLETE')
            xdr['msgType'] = 135
        else:
            print(xdr['display'], 'UnKnown IU RELEASE COMPLETE')
            xdr['msgTypeOriginal'] = 0x2001
            xdr['msgType'] = 0
    elif msgType == 0x2002:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS RELOCATION COMMAND')
            xdr['msgType'] = 747
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS RELOCATION COMMAND')
            xdr['msgType'] = 147
        else:
            print(xdr['display'], 'UnKnown RELOCATION COMMAND')
            xdr['msgTypeOriginal'] = 0x2002
            xdr['msgType'] = 0
    elif msgType == 0x2003:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RELOCATION REQUEST ACKNOWLEDGE')
            xdr['msgType'] = 748
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RELOCATION REQUEST ACKNOWLEDGE')
            xdr['msgType'] = 150
        else:
            print(xdr['display'], 'UnKnown RELOCATION REQUEST ACKNOWLEDGE')
            xdr['msgTypeOriginal'] = 0x2003
            xdr['msgType'] = 0
    elif msgType == 0x2004:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS RELOCATION CANCEL ACKNOWLEDGE')
            xdr['msgType'] = 749
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS RELOCATION CANCEL ACKNOWLEDGE')
            xdr['msgType'] = 146
        else:
            print(xdr['display'], 'UnKnown RELOCATION CANCEL ACKNOWLEDGE')
            xdr['msgTypeOriginal'] = 0x2004
            xdr['msgType'] = 0
    elif msgType == 0x2005:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS SRNS CONTEXT RESPONSE')
            xdr['msgType'] = 750
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS SRNS CONTEXT RESPONSE')
            xdr['msgType'] = 174
        else:
            print(xdr['display'], 'UnKnown SRNS CONTEXT RESPONSE')
            xdr['msgTypeOriginal'] = 0x2005
            xdr['msgType'] = 0
    elif msgType == 0x2006:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS SECURITY MODE COMPLETE')
            xdr['msgType'] = 751
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS SECURITY MODE COMPLETE')
            xdr['msgType'] = 156
        else:
            print(xdr['display'], 'UnKnown SECURITY MODE COMPLETE')
            xdr['msgTypeOriginal'] = 0x2006
            xdr['msgType'] = 0
    elif msgType == 0x2007:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS DATA VOLUME REPORT')
            xdr['msgType'] = 752
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS DATA VOLUME REPORT')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown DATA VOLUME REPORT')
            xdr['msgTypeOriginal'] = 0x2007
            xdr['msgType'] = 0
    elif msgType == 0x2009:
        xdr['dir'] = '0'
        if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
            xdr['dir'] = '1'
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS RESET ACKNOWLEDGE')
            xdr['msgType'] = 753
            xdr['dir'] = '1'
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS RESET ACKNOWLEDGE')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '1'
        elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RESET ACKNOWLEDGE')
            xdr['msgType'] = 753
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RESET ACKNOWLEDGE')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '0'
        else:
            print(xdr['display'], 'UnKnown RESET ACKNOWLEDGE')
            xdr['msgTypeOriginal'] = 0x2009
            xdr['msgType'] = 0
    elif msgType == 0x201B:
        xdr['dir'] = '0'
        if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
            xdr['dir'] = '1'
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS RESET RESOURCE ACKNOWLEDGE')
            xdr['msgType'] = 754
            xdr['dir'] = '1'
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS RESET RESOURCE ACKNOWLEDGE')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '1'
        elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RESET RESOURCE ACKNOWLEDGE')
            xdr['msgType'] = 754
            xdr['dir'] = '0'
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RESET RESOURCE ACKNOWLEDGE')
            # xdr['msgType'] = 
            return
            xdr['dir'] = '0'
        else:
            print(xdr['display'], 'UnKnown RESET RESOURCE ACKNOWLEDGE')
            xdr['msgTypeOriginal'] = 0x201B
            xdr['msgType'] = 0
    elif msgType == 0x201E:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS LOCATION RELATED DATA RESPONSE')
            xdr['msgType'] = 755
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS LOCATION RELATED DATA RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown LOCATION RELATED DATA RESPONSE')
            xdr['msgTypeOriginal'] = 0x201E
            xdr['msgType'] = 0
    elif msgType == 0x201F:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS INFORMATION TRANSFER CONFIRMATION')
            xdr['msgType'] = 756
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS INFORMATION TRANSFER CONFIRMATION')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown INFORMATION TRANSFER CONFIRMATION')
            xdr['msgTypeOriginal'] = 0x201F
            xdr['msgType'] = 0
    elif msgType == 0x2021:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS UPLINK INFORMATION EXCHANGE RESPONSE')
            xdr['msgType'] = 757
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS UPLINK INFORMATION EXCHANGE RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown UPLINK INFORMATION EXCHANGE RESPONSE')
            xdr['msgTypeOriginal'] = 0x2021
            xdr['msgType'] = 0
    elif msgType == 0x2023:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS SESSION START RESPONSE')
            xdr['msgType'] = 758
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS SESSION START RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS SESSION START RESPONSE')
            xdr['msgTypeOriginal'] = 0x2023
            xdr['msgType'] = 0
    elif msgType == 0x2024:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS SESSION UPDATE RESPONSE')
            xdr['msgType'] = 759
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS SESSION UPDATE RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS SESSION UPDATE RESPONSE')
            xdr['msgTypeOriginal'] = 0x2024
            xdr['msgType'] = 0
    elif msgType == 0x2025:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS SESSION STOP RESPONSE')
            xdr['msgType'] = 760
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS SESSION STOP RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS SESSION STOP RESPONSE')
            xdr['msgTypeOriginal'] = 0x2025
            xdr['msgType'] = 0
    elif msgType == 0x2026:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS UE LINKING RESPONSE')
            xdr['msgType'] = 761
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS UE LINKING RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS UE LINKING RESPONSE')
            xdr['msgTypeOriginal'] = 0x2026
            xdr['msgType'] = 0
    elif msgType == 0x2027:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS REGISTRATION RESPONSE')
            xdr['msgType'] = 762
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS REGISTRATION RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS REGISTRATION RESPONSE')
            xdr['msgTypeOriginal'] = 0x2027
            xdr['msgType'] = 0
    elif msgType == 0x2028:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS CN DE-REGISTRATION RESPONSE')
            xdr['msgType'] = 763
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS CN DE-REGISTRATION RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS CN DE-REGISTRATION RESPONSE')
            xdr['msgTypeOriginal'] = 0x2028
            xdr['msgType'] = 0
    elif msgType == 0x202A:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS RAB RELEASE')
            xdr['msgType'] = 764
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS RAB RELEASE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS RAB RELEASE')
            xdr['msgTypeOriginal'] = 0x202A
            xdr['msgType'] = 0
    elif msgType == 0x202B:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS ENHANCED RELOCATION COMPLETE RESPONSE')
            xdr['msgType'] = 765
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS ENHANCED RELOCATION COMPLETE RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown ENHANCED RELOCATION COMPLETE RESPONSE')
            xdr['msgTypeOriginal'] = 0x202B
            xdr['msgType'] = 0
    elif msgType == 0x202D:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RANAP ENHANCED RELOCATION INFORMATION RESPONSE')
            xdr['msgType'] = 766
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RANAP ENHANCED RELOCATION INFORMATION RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown RANAP ENHANCED RELOCATION INFORMATION RESPONSE')
            xdr['msgTypeOriginal'] = 0x202D
            xdr['msgType'] = 0
    elif msgType == 0x202E:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS SRVCC CS KEYS RESPONSE')
            xdr['msgType'] = 767
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS SRVCC CS KEYS RESPONSE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown SRVCC CS KEYS RESPONSE')
            xdr['msgTypeOriginal'] = 0x202E
            xdr['msgType'] = 0
    elif msgType == 0x6000:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RAB ASSIGNMENT RESPONSE x N (N>=1)')
            xdr['msgType'] = 768
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RAB ASSIGNMENT RESPONSE x N (N>=1)')
            xdr['msgType'] = 143
        else:
            print(xdr['display'], 'UnKnown RAB ASSIGNMENT RESPONSE x N (N>=1)')
            xdr['msgTypeOriginal'] = 0x6000
            xdr['msgType'] = 0
    elif msgType == 0x4002:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS RELOCATION PREPARATION FAILURE')
            xdr['msgType'] = 769
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS RELOCATION PREPARATION FAILURE')
            xdr['msgType'] = 153
        else:
            print(xdr['display'], 'UnKnown RELOCATION PREPARATION FAILURE')
            xdr['msgTypeOriginal'] = 0x4002
            xdr['msgType'] = 0
    elif msgType == 0x4003:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS RELOCATION FAILURE')
            xdr['msgType'] = 770
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS RELOCATION FAILURE')
            xdr['msgType'] = 152
        else:
            print(xdr['display'], 'UnKnown RELOCATION FAILURE')
            xdr['msgTypeOriginal'] = 0x4003
            xdr['msgType'] = 0
    elif msgType == 0x4006:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS SECURITY MODE REJECT')
            xdr['msgType'] = 771
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS SECURITY MODE REJECT')
            xdr['msgType'] = 157
        else:
            print(xdr['display'], 'UnKnown SECURITY MODE REJECT')
            xdr['msgTypeOriginal'] = 0x4006
            xdr['msgType'] = 0
    elif msgType == 0x401E:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS LOCATION RELATED DATA FAILURE')
            xdr['msgType'] = 772
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS LOCATION RELATED DATA FAILURE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown LOCATION RELATED DATA FAILURE')
            xdr['msgTypeOriginal'] = 0x401E
            xdr['msgType'] = 0
    elif msgType == 0x401F:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS INFORMATION TRANSFER FAILURE')
            xdr['msgType'] = 773
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS INFORMATION TRANSFER FAILURE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown INFORMATION TRANSFER FAILURE')
            xdr['msgTypeOriginal'] = 0x401F
            xdr['msgType'] = 0
    elif msgType == 0x4021:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS UPLINK INFORMATION EXCHANGE FAILURE')
            xdr['msgType'] = 774
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS UPLINK INFORMATION EXCHANGE FAILURE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown UPLINK INFORMATION EXCHANGE FAILURE')
            xdr['msgTypeOriginal'] = 0x4021
            xdr['msgType'] = 0
    elif msgType == 0x4023:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS SESSION START FAILURE')
            xdr['msgType'] = 775
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS SESSION START FAILURE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS SESSION START FAILURE')
            xdr['msgTypeOriginal'] = 0x4023
            xdr['msgType'] = 0
    elif msgType == 0x4024:
        xdr['dir'] = '0'
        if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
        if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS SESSION UPDATE FAILURE')
            xdr['msgType'] = 776
        elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS SESSION UPDATE FAILURE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS SESSION UPDATE FAILURE')
            xdr['msgTypeOriginal'] = 0x4024
            xdr['msgType'] = 0
    elif msgType == 0x4027:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS REGISTRATION FAILURE')
            xdr['msgType'] = 777
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS REGISTRATION FAILURE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS REGISTRATION FAILURE')
            xdr['msgTypeOriginal'] = 0x4027
            xdr['msgType'] = 0
    elif msgType == 0x402A:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS MBMS RAB RELEASE FAILURE')
            xdr['msgType'] = 778
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS MBMS RAB RELEASE FAILURE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown MBMS RAB RELEASE FAILURE')
            xdr['msgTypeOriginal'] = 0x402A
            xdr['msgType'] = 0
    elif msgType == 0x402B:
        xdr['dir'] = '1'
        if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
        if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
            print(xdr['display'], 'IuCS ENHANCED RELOCATION COMPLETE FAILURE')
            xdr['msgType'] = 779
        elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
            print(xdr['display'], 'IuPS ENHANCED RELOCATION COMPLETE FAILURE')
            # xdr['msgType'] = 
            return
        else:
            print(xdr['display'], 'UnKnown ENHANCED RELOCATION COMPLETE FAILURE')
            xdr['msgTypeOriginal'] = 0x402B
            xdr['msgType'] = 0
    cacheRANAPXDR(xdr)
    return

def decodeBSSAP(xdr,raw):
    xdr['Network'] = 2
    msgType = struct.unpack('!B',raw[0:1])[0]
    if msgType == 0:                                   # BSS Management (0x00)
        xdr['display'] += ', BSSMAP'
        msgLength = struct.unpack('!B',raw[1:2])[0]
        if msgLength != len(raw) - 2:
            print(xdr['display'],'Not BSSAP not decoded')
            del xdr,raw
            return
        bssmapType = struct.unpack('!B',raw[2:3])[0]
        i = 3
        xdr['msgType'] = bssmap.get(bssmapType,0)
        
        if xdr['msgType'] == 1100:
            print(xdr['display'],'ASSIGNMENT REQUEST')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1101:
            print(xdr['display'],'ASSIGNMENT COMPLETE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1102:
            print(xdr['display'],'ASSIGNMENT FAILURE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1103:
            print(xdr['display'],'CHANNEL MODIFY REQUEST')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1104:
            print(xdr['display'],'HANDOVER REQUEST')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1105:
            print(xdr['display'],'HANDOVER REQUIRED')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1106:
            print(xdr['display'],'HANDOVER REQUEST ACKNOWLEDGE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1107:
            print(xdr['display'],'HANDOVER COMMAND')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1108:
            print(xdr['display'],'HANDOVER COMPLETE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1109:
            print(xdr['display'],'HANDOVER SUCCEEDED')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1110:
            print(xdr['display'],'HANDOVER FAILURE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1111:
            print(xdr['display'],'HANDOVER PERFORMED')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1112:
            print(xdr['display'],'HANDOVER CANDIDATE ENQUIRE')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1113:
            print(xdr['display'],'HANDOVER CANDIDATE RESPONSE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1114:
            print(xdr['display'],'HANDOVER REQUIRED REJECT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1115:
            print(xdr['display'],'HANDOVER DETECT')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1116:
            print(xdr['display'],'INTERNAL HANDOVER REQUIRED')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1117:
            print(xdr['display'],'INTERNAL HANDOVER REQUIRED REJECT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1118:
            print(xdr['display'],'INTERNAL HANDOVER COMMAND')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1119:
            print(xdr['display'],'INTERNAL HANDOVER ENQUIRY')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1120:
            print(xdr['display'],'SUSPEND')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1121:
            print(xdr['display'],'RESUME')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1122:
            print(xdr['display'],'PERFORM LOCATION REQUEST')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1123:
            print(xdr['display'],'LSA INFORMATION')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1124:
            print(xdr['display'],'PERFORM LOCATION RESPONSE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1125:
            print(xdr['display'],'PERFORM LOCATION ABORT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1126:
            print(xdr['display'],'COMMON ID')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1127:
            print(xdr['display'],'REROUTE COMMAND')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1128:
            print(xdr['display'],'REROUTE COMPLETE')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1129:
            print(xdr['display'],'CONNECTIONLESS INFORMATION')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 1130:
            print(xdr['display'],'RESOURCE REQUEST')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1131:
            print(xdr['display'],'RESOURCE INDICATION')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1132:
            print(xdr['display'],'PAGING')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])

            # book mark
        elif xdr['msgType'] == 1133:
            print(xdr['display'],'CIPHER MODE COMMAND')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1134:
            print(xdr['display'],'CLASSMARK UPDATE')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 1135:
            print(xdr['display'],'CIPHER MODE COMPLETE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1136:
            print(xdr['display'],'QUEUING INDICATION')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1137:
            print(xdr['display'],'COMPLETE LAYER 3 INFORMATION')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            totalLength = len(raw)
            while i < totalLength:
                eleID = struct.unpack('!B',raw[i:i+1])[0]
                i += 1
                if eleID == 0:
                    break
                elif eleID == 5:
                    eleLength,eleType = struct.unpack('!2B',raw[i:i+2])
                    i += 1
                    if eleLength == 8 and eleType & 15 == 0:
                        lac,ci = struct.unpack('!2H',raw[i+4:i+4+4])
                        xdr['cgi'] = (lac << 16) + ci
                    i += eleLength
                elif eleID == 0x17:                      # Layer 3 Information
                    eleLength = struct.unpack('!2B',raw[i:i+2])[0]
                    i += 1
                    tempxdr = xdr.copy()
                    decodeL3Msg(tempxdr,raw[i:i+eleLength])
                    i += eleLength
                elif eleID == 0x21:                      # Chosen Channel
                    i += 1
                elif eleID == 0x85:
                    pass
                elif eleID == 0x87:
                    i += 1
                else:
                    eleLength = struct.unpack('!B',raw[i:i+1])[0]
                    i += eleLength + 1
        elif xdr['msgType'] == 1138:
            print(xdr['display'],'CLASSMARK REQUEST')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1139:
            print(xdr['display'],'CIPHER MODE REJECT')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1140:
            print(xdr['display'],'VGCS/VBS SETUP')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1141:
            print(xdr['display'],'VGCS/VBS SETUP ACK')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1142:
            print(xdr['display'],'VGCS/VBS SETUP REFUSE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1143:
            print(xdr['display'],'VGCS/VBS ASSIGNMENT REQUEST')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1144:
            print(xdr['display'],'VGCS/VBS ASSIGNMENT RESULT')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1145:
            print(xdr['display'],'VGCS/VBS ASSIGNMENT FAILURE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1146:
            print(xdr['display'],'VGCS/VBS QUEUING INDICATION')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1147:
            print(xdr['display'],'VGCS/VBS ASSIGNMENT STATUS')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1148:
            print(xdr['display'],'VGCS/VBS AREA CELL INFO')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1149:
            print(xdr['display'],'UPLINK REQUEST')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1150:
            print(xdr['display'],'UPLINK REQUEST ACKNOWLEDGE')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1151:
            print(xdr['display'],'UPLINK REQUEST CONFIRMATION')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1152:
            print(xdr['display'],'UPLINK RELEASE INDICATION')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1153:
            print(xdr['display'],'UPLINK REJECT COMMAND')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1154:
            print(xdr['display'],'UPLINK RELEASE COMMAND')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1155:
            print(xdr['display'],'UPLINK SEIZED COMMAND')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1156:
            print(xdr['display'],'VGCS ADDITIONAL INFORMATION')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1157:
            print(xdr['display'],'VGCS SMS')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1158:
            print(xdr['display'],'NOTIFICATION DATA')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1159:
            print(xdr['display'],'UPLINK APPLICATION DATA')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1160:
            print(xdr['display'],'LCLS-CONNECT-CONTROL')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1161:
            print(xdr['display'],'LCLS-CONNECT-CONTROL-ACK')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1162:
            print(xdr['display'],'LCLS-NOTIFICATION')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1163:
            print(xdr['display'],'CLEAR COMMAND')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 1164:
            print(xdr['display'],'CLEAR COMPLETE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 1165:
            print(xdr['display'],'CLEAR REQUEST')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        else:
            print(xdr['display'],'Unknown BSSAP Message')

    elif msgType == 1:                # DTAP Direct Transfer Application Part (0x01)
        xdr['display'] += ', DTAP'
        if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
            xdr['dir'] = '0'
        else:
            xdr['dir'] = '1'
        msgLength = struct.unpack('!B',raw[2:3])[0]
        if msgLength != len(raw) - 3:
            print(xdr['display'],'Not DTAP not decoded')
            del xdr,raw
            return
        tempxdr = xdr.copy()
        decodeL3Msg(tempxdr,raw[3:3+msgLength])
    else:
        print('BSSAP Messgae Type is ', msgType)
        del xdr,raw
        return
    outputBSSAPXDR(xdr)
    return

def decodeL3Msg(xdr,raw):
    global ipMSC,ipRAN,pcMSC,pcRAN
    i = 0
    pd = struct.unpack('!B',raw[i:i+1])[0] & 15
    i += 1
    if pd == 3:                                       # call control; call related SS messages
        dtapMsgType = struct.unpack('!B',raw[i:i+1])[0] & 63
        i += 1
        xdr['msgType'] = mcCC.get(dtapMsgType,0)
        if xdr['msgType'] == 400:
            print(xdr['display'],'Alerting')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 405:
            print(xdr['display'],'Call Confirmed')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 435:
            print(xdr['display'],'Call Processing')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 411:
            print(xdr['display'],'Connect')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 412:
            print(xdr['display'],'Connect ACK')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 413:
            print(xdr['display'],'Disconnect')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 414:
            print(xdr['display'],'Energency Setup')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 436:
            print(xdr['display'],'Process')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 437:
            print(xdr['display'],'CC-establishment')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 438:
            print(xdr['display'],'CC-establishment confirmed')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 439:
            print(xdr['display'],'Recall')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 440:
            print(xdr['display'],'Start CC')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 441:
            print(xdr['display'],'Modify')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 442:
            print(xdr['display'],'Modify Complete')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 443:
            print(xdr['display'],'Modify Reject')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 444:
            print(xdr['display'],'User Information')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 415:
            print(xdr['display'],'Hold')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 416:
            print(xdr['display'],'Hold ACK')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 417:
            print(xdr['display'],'Hold Reject')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 425:
            print(xdr['display'],'Release')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 426:
            print(xdr['display'],'Release Complete')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 427:
            print(xdr['display'],'Retrieve')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 428:
            print(xdr['display'],'Retrieve ACK')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 429:
            print(xdr['display'],'Retrieve Reject')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 430:
            print(xdr['display'],'Setup')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 445:
            print(xdr['display'],'Congestion Control')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 446:
            print(xdr['display'],'Notify')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 447:
            print(xdr['display'],'Status')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 448:
            print(xdr['display'],'Status Enquiry')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 449:
            print(xdr['display'],'Start DTMF')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 450:
            print(xdr['display'],'Stop DTMF')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 451:
            print(xdr['display'],'Stop DTMF Ack')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 452:
            print(xdr['display'],'Start DTMF Ack')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 453:
            print(xdr['display'],'Start DTMF Rej')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 454:
            print(xdr['display'],'Facility')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        else:
            print(xdr['display'],mcCC.get(dtapMsgType,0),'not decoded')

    elif pd == 5:                                     # mobility management messages
        dtapMsgType = struct.unpack('!B',raw[i:i+1])[0] & 63
        xdr['msgType'] = mcMM.get(dtapMsgType,0)
        if xdr['msgType'] == 401:
            print(xdr['display'],'Authen Failure')
            xdr['Cause'] = struct.unpack('!B',raw[i+2:i+2+1])[0]
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 402:
            print(xdr['display'],'Authen Reject')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 403:
            print(xdr['display'],'Authen Request')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 404:
            print(xdr['display'],'Authen Response')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 406:
            print(xdr['display'],'CM Re-establishment Request')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 407:
            print(xdr['display'],'CM Service Abort')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 408:
            print(xdr['display'],'CM Service Accept')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 409:
            print(xdr['display'],'CM Service Reject')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 410:
            print(xdr['display'],'CM Service Request')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 433:
            print(xdr['display'],'CM Service Prompt')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 434:
            print(xdr['display'],'Abort')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 418:
            print(xdr['display'],'Identity Request')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 419:
            print(xdr['display'],'Identity Response')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 431:
            print(xdr['display'],'TMSI Reallocation Command')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 432:
            print(xdr['display'],'TMSI Reallocation Complete')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 420:
            print(xdr['display'],'IMSI Detach Indication')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 421:
            print(xdr['display'],'Location Update Accept')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 422:
            print(xdr['display'],'Location Update Reject')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 455:
            print(xdr['display'],'MM Null')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipMSC: ipMSC.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcMSC: pcMSC.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 456:
            print(xdr['display'],'MM Status')
            if xdr['dip'][0] in ipMSC or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcMSC or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 457:
            print(xdr['display'],'MM Information')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipMSC: ipMSC.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcMSC: pcMSC.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        else:
            print(xdr['display'],mcMM.get(dtapMsgType,0),'not decoded')
    elif pd == 8:                                     # GPRS mobility management messages
        dtapMsgType = struct.unpack('!B',raw[i:i+1])[0] & 63
        xdr['msgType'] = gprsMM.get(dtapMsgType,0)
        if xdr['msgType'] == 112:
            print(xdr['display'],'ATTACH_REQUEST')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 113:
            print(xdr['display'],'ATTACH_ACCEPT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 114:
            print(xdr['display'],'ATTACH_COMPLETE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 115:
            print(xdr['display'],'ATTACH_REJECT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 116:
            print(xdr['display'],'AUTH_AND_CIPHERING_REQUEST')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 117:
            print(xdr['display'],'AUTH_AND_CIPHERING_RESPONSE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 118:
            print(xdr['display'],'AUTH_AND_CIPHERING_REJECT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 119:
            print(xdr['display'],'AUTH_AND_CIPHERING_FAILURE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 120:
            print(xdr['display'],'DETACH_REQUEST')
            if xdr['dip'][0] in ipSGSN or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcSGSN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
                xdr['msgType'] = 176
        elif xdr['msgType'] == 121:
            print(xdr['display'],'DETACH_ACCEPT')
            if xdr['dip'][0] in ipSGSN or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcSGSN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 122:
            print(xdr['display'],'IDENTITY_REQUEST')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 123:
            print(xdr['display'],'IDENTITY_RESPONSE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 124:
            print(xdr['display'],'RAU_REQUEST')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 125:
            print(xdr['display'],'RAU_ACCEPT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 126:
            print(xdr['display'],'RAU_COMPLETE')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 127:
            print(xdr['display'],'RAU_REJECT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 128:
            print(xdr['display'],'SERVICE_REQUEST')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 129:
            print(xdr['display'],'SERVICE_ACCEPT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 130:
            print(xdr['display'],'SERVICE_REJECT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        else:
            print(xdr['display'],gprsMM.get(dtapMsgType,0),'not decoded')
    elif pd == 10:                                     # GPRS session management messages
        dtapMsgType = struct.unpack('!B',raw[i:i+1])[0] & 63
        xdr['msgType'] = gprsMM.get(dtapMsgType,0)
        if xdr['msgType'] == 158:
            print(xdr['display'],'ACTIVATE_2nd_PDP_CONTEXT_REQUEST')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 159:
            print(xdr['display'],'ACTIVATE_2nd_PDP_CONTEXT_ACCEPT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 160:
            print(xdr['display'],'ACTIVATE_2nd_PDP_CONTEXT_REJECT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 161:
            print(xdr['display'],'ACTIVATE_PDP_CONTEXT_REQUEST')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 162:
            print(xdr['display'],'ACTIVATE_PDP_CONTEXT_ACCEPT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 163:
            print(xdr['display'],'ACTIVATE_PDP_CONTEXT_REJECT')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 164:
            print(xdr['display'],'DEACTIVATE_PDP_CONTEXT_REQUEST')
            if xdr['dip'][0] in ipSGSN or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcSGSN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 165:
            print(xdr['display'],'DEACTIVATE_PDP_CONTEXT_ACCEPT')
            if xdr['dip'][0] in ipSGSN or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcSGSN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 166:
            print(xdr['display'],'MODIFY_PDP_CONTEXT_REQUEST(UL)')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 167:
            print(xdr['display'],'MODIFY_PDP_CONTEXT_REQUEST(DL)')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 168:
            print(xdr['display'],'MODIFY_PDP_CONTEXT_ACCEPT(UL)')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        elif xdr['msgType'] == 169:
            print(xdr['display'],'MODIFY_PDP_CONTEXT_ACCEPT(DL)')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 170:
            print(xdr['display'],'MODIFY_PDP_CONTEXT_REJECT')
            if xdr['dip'][0] in ipSGSN or xdr['sip'][0] in ipRAN or xdr['dpc'] in pcSGSN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            else:
                xdr['dir'] = '1'
        elif xdr['msgType'] == 171:
            print(xdr['display'],'REQUEST_PDP_CONTEXT_ACTIVATION')
            xdr['dir'] = '1'
            if xdr['sip'][0] not in ipSGSN: ipSGSN.append(xdr['sip'][0])
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['opc'] not in pcSGSN: pcSGSN.append(xdr['opc'])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
        elif xdr['msgType'] == 172:
            print(xdr['display'],'REQUEST_PDP_CONTEXT_ACTIVATION_REJECT')
            xdr['dir'] = '0'
            if xdr['dip'][0] not in ipSGSN: ipSGSN.append(xdr['dip'][0])
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['dpc'] not in pcSGSN: pcSGSN.append(xdr['dpc'])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
        else:
            print(xdr['display'],gprsSM.get(dtapMsgType,0),'not decoded')
    else:
        print(xdr['display'],ProtocolDiscriminator[pd])
        del xdr,raw
        return
    
    if xdr['msgType'] >= 400:
        outputMCXDR(xdr)
    else:
        outputGPRSXDR(xdr)
    return

def outputBICCXDR(xdr):
    global biccOutputFile,biccCPLatencyOutputFile
    if xdr['msgType'] != 0:
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
        ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
        if len(xdr['sip'][-1]) == 4:
            sip = inet_ntoa(xdr['sip'][-1])
            dip = inet_ntoa(xdr['dip'][-1])
        elif len(xdr['sip'][-1]) == 16:
            sip = inet_ntop(AF_INET6, xdr['sip'][-1])
            dip = inet_ntop(AF_INET6, xdr['dip'][-1])
        xdr['interface'] = 'Nc'
        if(xdr['imsi'] == '0'): xdr['imsi'] = ''
        if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
        # status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],".".join([str((int(xdr['opc'])>>11)%8),str((int(xdr['opc'])>>3)%256),str(int(xdr['opc'])%8)]),".".join([str((int(xdr['dpc'])>>11)%8),str((int(xdr['dpc'])>>3)%256),str(int(xdr['dpc'])%8)]),'','',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))
        status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'PC-'+str(xdr['opc']),'PC-'+str(xdr['dpc']),'','',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

        if biccOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            biccOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_Nc_Msg_'+b+'.tmp')
            biccOutputFile = open(biccOutputFileName,'w')
            if biccOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(biccOutputFile)
        biccOutputFile.writelines(string)
    return

def cacheBICCXDR(xdr):
    # biccXDR.append(xdr)
    outputBICCXDR(xdr)
    return

def flushBICCXDR():
    status.callFlow.sort(key=lambda x:x['ts1'])
    for xdr in status.callFlow:
        print('Call Flow:',xdr['msgType'],xdr['ts'][0]*1000000000+xdr['ts'][1],xdr.get('TSN',0),xdr.get('streamID',0),xdr.get('streamSeq',0),xdr.get('biccHopCounter',0),xdr.get('biccCallID',0),xdr.get('biccSPC',0),xdr.get('biccOriginalCalledNumber',0),xdr.get('Receiver',0))
    for i in range(len(status.callFlow)):
        xdr = status.callFlow[i]
            
    # generate the network topology based in opc,dpc
    
    
    
    # matching ip with network topolpgy based on opc,doc
    
    # matching xdr with network topology

    # output the rest msg

    return

def outputMCXDR(xdr):
    global mcOutputFile,mcCPLatencyOutputFile
    if xdr['imsi'] == '0': xdr['imsi'] = str(888880000000000+int(xdr['sport'])+int(xdr['dport']))
    if xdr['msgType'] != 0:
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
        ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
        if len(xdr['sip'][-1]) == 4:
            sip = inet_ntoa(xdr['sip'][-1])
            dip = inet_ntoa(xdr['dip'][-1])
        elif len(xdr['sip'][-1]) == 16:
            sip = inet_ntop(AF_INET6, xdr['sip'][-1])
            dip = inet_ntop(AF_INET6, xdr['dip'][-1])
        xdr['interface'] = 'Mc'
        if(xdr['imsi'] == '0'): xdr['imsi'] = ''
        if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
        status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'PC-'+str(xdr['opc']),'PC-'+str(xdr['dpc']),'','',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

        if mcOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            mcOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_Mc_Msg_'+b+'.tmp')
            mcOutputFile = open(mcOutputFileName,'w')
            if mcOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(mcOutputFile)
        mcOutputFile.writelines(string)
    return
def outputGPRSXDR(xdr):
    global gprsOutputFile,gpesCPLatencyOutputFile
    if xdr['imsi'] == '0': xdr['imsi'] = str(888880000000000+int(xdr['sport'])+int(xdr['dport']))
    if xdr['msgType'] != 0:
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
        status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'PC-'+str(xdr['opc']),'PC-'+str(xdr['dpc']),'','',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

        if gprsOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            gprsOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_NAS_Msg_'+b+'.tmp')
            gprsOutputFile = open(gprsOutputFileName,'w')
            if gprsOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(gprsOutputFile)
        gprsOutputFile.writelines(string)
    return
def outputRANAPXDR(xdr):
    global ranapOutputFile,ranapCPLatencyOutputFile
    if xdr['imsi'] == '0': xdr['imsi'] = str(888880000000000+int(xdr['sport'])+int(xdr['dport']))
    if xdr['msgType'] != 0:
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
        ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
        if len(xdr['sip'][-1]) == 4:
            sip = inet_ntoa(xdr['sip'][-1])
            dip = inet_ntoa(xdr['dip'][-1])
        elif len(xdr['sip'][-1]) == 16:
            sip = inet_ntop(AF_INET6, xdr['sip'][-1])
            dip = inet_ntop(AF_INET6, xdr['dip'][-1])
        xdr['interface'] = 'Iu'
        if(xdr['imsi'] == '0'): xdr['imsi'] = ''
        if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
        status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'PC-'+str(xdr['opc']),'PC-'+str(xdr['dpc']),'','',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

        if ranapOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            ranapOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_Iu_Msg_'+b+'.tmp')
            ranapOutputFile = open(ranapOutputFileName,'w')
            if ranapOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(ranapOutputFile)
        ranapOutputFile.writelines(string)
    return

def cacheRANAPXDR(xdr):
    if xdr['msgType'] == 0:
        ranapXDR.append(xdr)
    else:
        outputRANAPXDR(xdr)
def flushRANAPXDR():
    defaultInterface = 'PS'
    if len(pcMSC) != 0 and len(pcSGSN) == 0:
        defaultInterface = 'CS'

    for xdr in ranapXDR:
        msgType = xdr['msgTypeOriginal']
        if msgType == 0x0001:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS IU RELEASE COMMAND')
                xdr['msgType'] = 700
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS IU RELEASE COMMAND')
                xdr['msgType'] = 134
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 700
                else:
                    xdr['msgType'] = 134
        elif msgType == 0x0002:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RELOCATION REQUIRED')
                xdr['msgType'] = 701
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RELOCATION REQUIRED')
                xdr['msgType'] = 154
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 701
                else:
                    xdr['msgType'] = 154
        elif msgType == 0x0003:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS RELOCATION REQUEST')
                xdr['msgType'] = 702
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS RELOCATION REQUEST')
                xdr['msgType'] = 149
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 702
                else:
                    xdr['msgType'] = 149
        elif msgType == 0x0004:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RELOCATION CANCEL')
                xdr['msgType'] = 703
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RELOCATION CANCEL')
                xdr['msgType'] = 145
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 703
                else:
                    xdr['msgType'] = 145
        elif msgType == 0x0005:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS SRNS CONTEXT REQUEST')
                xdr['msgType'] = 704
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS SRNS CONTEXT REQUEST')
                xdr['msgType'] = 173
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 704
                else:
                    xdr['msgType'] = 173
        elif msgType == 0x0006:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS SECURITY MODE COMMAND')
                xdr['msgType'] = 705
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS SECURITY MODE COMMAND')
                xdr['msgType'] = 155
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 705
                else:
                    xdr['msgType'] = 155
        elif msgType == 0x0007:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS DATA VOLUME REPORT REQUEST')
                xdr['msgType'] = 706
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS DATA VOLUME REPORT REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 706
        elif msgType == 0x0009:
            xdr['dir'] = '0'
            if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
                xdr['dir'] = '1'
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS RESET')
                xdr['msgType'] = 707
                xdr['dir'] = '1'
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS RESET')
                # xdr['msgType'] =
                xdr['dir'] = '1'
                return
            elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RESET')
                xdr['msgType'] = 707
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RESET')
                # xdr['msgType'] =
                xdr['dir'] = '0'
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 707
        elif msgType == 0x001B:
            xdr['dir'] = '0'
            if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
                xdr['dir'] = '1'
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS RESET RESOURCE')
                xdr['msgType'] = 708
                xdr['dir'] = '1'
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS RESET RESOURCE')
                # xdr['msgType'] =
                xdr['dir'] = '1'
                return
            elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RESET RESOURCE')
                xdr['msgType'] = 708
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RESET RESOURCE')
                # xdr['msgType'] =
                return
                xdr['dir'] = '0'
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 708
        elif msgType == 0x001E:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS LOCATION RELATED DATA REQUEST')
                xdr['msgType'] = 709
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS LOCATION RELATED DATA REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 709
        elif msgType == 0x001F:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS INFORMATION TRANSFER INDICATION')
                xdr['msgType'] = 710
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS INFORMATION TRANSFER INDICATION')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 710
        elif msgType == 0x0021:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS UPLINK INFORMATION EXCHANGE REQUEST')
                xdr['msgType'] = 711
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS UPLINK INFORMATION EXCHANGE REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 711
        elif msgType == 0x0023:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS SESSION START')
                xdr['msgType'] = 712
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS SESSION START')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 712
        elif msgType == 0x0024:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS SESSION UPDATE')
                xdr['msgType'] = 713
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS SESSION UPDATE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 713
        elif msgType == 0x0025:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS SESSION STOP REQUEST')
                xdr['msgType'] = 714
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS SESSION STOP REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 714
        elif msgType == 0x0026:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS UE LINKING REQUEST')
                xdr['msgType'] = 715
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS UE LINKING REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 715
        elif msgType == 0x0027:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS REGISTRATION REQUEST')
                xdr['msgType'] = 716
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS REGISTRATION REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 716
        elif msgType == 0x0028:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS CN DE-REGISTRATION REQUEST')
                xdr['msgType'] = 717
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS CN DE-REGISTRATION REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 717
        elif msgType == 0x002A:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS RAB RELEASE REQUEST')
                xdr['msgType'] = 718
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS RAB RELEASE REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 718
        elif msgType == 0x002B:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS ENHANCED RELOCATION COMPLETE REQUEST')
                xdr['msgType'] = 719
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS ENHANCED RELOCATION COMPLETE REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 719
        elif msgType == 0x002D:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RANAP ENHANCED RELOCATION INFORMATION REQUEST')
                xdr['msgType'] = 720
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RANAP ENHANCED RELOCATION INFORMATION REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 720
        elif msgType == 0x002E:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS SRVCC CS KEYS REQUEST')
                xdr['msgType'] = 721
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS SRVCC CS KEYS REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 721
        elif msgType == 0x001D:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RAB MODIFY REQUEST')
                xdr['msgType'] = 722
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RAB MODIFY REQUEST')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 722
        elif msgType == 0x000A:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RAB RELEASE REQUEST')
                xdr['msgType'] = 723
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RAB RELEASE REQUEST')
                xdr['msgType'] = 144
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 723
                else:
                    xdr['msgType'] = 144
        elif msgType == 0x000B:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS IU RELEASE REQUEST')
                xdr['msgType'] = 724
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS IU RELEASE REQUEST')
                xdr['msgType'] = 136
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 724
                else:
                    xdr['msgType'] = 136
        elif msgType == 0x000C:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RELOCATION DETECT')
                xdr['msgType'] = 725
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RELOCATION DETECT')
                xdr['msgType'] = 151
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 725
                else:
                    xdr['msgType'] = 151
        elif msgType == 0x000D:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RELOCATION COMPLETE')
                xdr['msgType'] = 726
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RELOCATION COMPLETE')
                xdr['msgType'] = 148
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 726
                else:
                    xdr['msgType'] = 148
        elif msgType == 0x001C:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RANAP RELOCATION INFORMATION')
                xdr['msgType'] = 727
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RANAP RELOCATION INFORMATION')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 727
        elif msgType == 0x0017:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS SRNS DATA FORWARD COMMAND')
                xdr['msgType'] = 728
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS SRNS DATA FORWARD COMMAND')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 728
        elif msgType == 0x0018:
            xdr['dir'] = '0'
            if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
                xdr['dir'] = '1'
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS FORWARD SRNS CONTEXT')
                xdr['msgType'] = 730
                xdr['dir'] = '1'
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS FORWARD SRNS CONTEXT')
                xdr['msgType'] = 175
                xdr['dir'] = '1'
            elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS FORWARD SRNS CONTEXT')
                xdr['msgType'] = 729
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS FORWARD SRNS CONTEXT')
                xdr['msgType'] = 175
                xdr['dir'] = '0'
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 729
                else:
                    xdr['msgType'] = 175
        elif msgType == 0x000E:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS PAGING')
                xdr['msgType'] = 731
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS PAGING')
                xdr['msgType'] = 131
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 731
                else:
                    xdr['msgType'] = 131
        elif msgType == 0x000F:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS COMMON ID')
                xdr['msgType'] = 732
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS COMMON ID')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 732
        elif msgType == 0x0010:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS CN INVOKE TRACE')
                xdr['msgType'] = 733
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS CN INVOKE TRACE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 733
        elif msgType == 0x001A:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS CN DEACTIVATE TRACE')
                xdr['msgType'] = 734
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS CN DEACTIVATE TRACE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 734
        elif msgType == 0x0011:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS LOCATION REPORTING CONTROL')
                xdr['msgType'] = 735
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS LOCATION REPORTING CONTROL')
                xdr['msgType'] = 138
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 735
                else:
                    xdr['msgType'] = 138
        elif msgType == 0x0012:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS LOCATION REPORT')
                xdr['msgType'] = 736
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS LOCATION REPORT')
                xdr['msgType'] = 137
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 736
                else:
                    xdr['msgType'] = 137
        elif msgType == 0x0013:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS INITIAL UE MESSAGE')
                xdr['msgType'] = 737
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS INITIAL UE MESSAGE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 737
        elif msgType == 0x0014:
            xdr['dir'] = '0'
            if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
                xdr['dir'] = '1'
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS DIRECT TRANSFER')
                xdr['msgType'] = 738
                xdr['dir'] = '1'
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS DIRECT TRANSFER')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '1'
            elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS DIRECT TRANSFER')
                xdr['msgType'] = 738
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS DIRECT TRANSFER')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '0'
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 738
        elif msgType == 0x0015:
            xdr['dir'] = '0'
            if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
                xdr['dir'] = '1'
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS OVERLOAD')
                xdr['msgType'] = 739
                xdr['dir'] = '1'
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS OVERLOAD')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '1'
            elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS OVERLOAD')
                xdr['msgType'] = 739
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS OVERLOAD')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '0'
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 739
        elif msgType == 0x0016:
            xdr['dir'] = '0'
            if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
                xdr['dir'] = '1'
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS ERROR INDICATION')
                xdr['msgType'] = 740
                xdr['dir'] = '1'
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS ERROR INDICATION')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '1'
            elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS ERROR INDICATION')
                xdr['msgType'] = 740
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS ERROR INDICATION')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '0'
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 740
        elif msgType == 0x0020:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS UE SPECIFIC INFORMATION INDICATION')
                xdr['msgType'] = 741
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS UE SPECIFIC INFORMATION INDICATION')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 741
        elif msgType == 0x0022:
            xdr['dir'] = '0'
            if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
                xdr['dir'] = '1'
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS DIRECT INFORMATION TRANSFER')
                xdr['msgType'] = 742
                xdr['dir'] = '1'
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS DIRECT INFORMATION TRANSFER')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '1'
            elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS DIRECT INFORMATION TRANSFER')
                xdr['msgType'] = 742
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS DIRECT INFORMATION TRANSFER')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '0'
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 742
        elif msgType == 0x0029:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS RAB ESTABLISHMENT INDICATION')
                xdr['msgType'] = 743
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS RAB ESTABLISHMENT INDICATION')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 743
        elif msgType == 0x002C:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS ENHANCED RELOCATION COMPLETE CONFIRM')
                xdr['msgType'] = 744
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS ENHANCED RELOCATION COMPLETE CONFIRM')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 744
        elif msgType == 0x0000:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS RAB ASSIGNMENT REQUEST')
                xdr['msgType'] = 745
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS RAB ASSIGNMENT REQUEST')
                xdr['msgType'] = 142
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 745
                else:
                    xdr['msgType'] = 142
        elif msgType == 0x2001:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS IU RELEASE COMPLETE')
                xdr['msgType'] = 746
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS IU RELEASE COMPLETE')
                xdr['msgType'] = 135
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 746
                else:
                    xdr['msgType'] = 135
        elif msgType == 0x2002:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS RELOCATION COMMAND')
                xdr['msgType'] = 747
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS RELOCATION COMMAND')
                xdr['msgType'] = 147
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 747
                else:
                    xdr['msgType'] = 147
        elif msgType == 0x2003:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RELOCATION REQUEST ACKNOWLEDGE')
                xdr['msgType'] = 748
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RELOCATION REQUEST ACKNOWLEDGE')
                xdr['msgType'] = 150
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 748
                else:
                    xdr['msgType'] = 150
        elif msgType == 0x2004:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS RELOCATION CANCEL ACKNOWLEDGE')
                xdr['msgType'] = 749
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS RELOCATION CANCEL ACKNOWLEDGE')
                xdr['msgType'] = 146
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 749
                else:
                    xdr['msgType'] = 146
        elif msgType == 0x2005:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS SRNS CONTEXT RESPONSE')
                xdr['msgType'] = 750
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS SRNS CONTEXT RESPONSE')
                xdr['msgType'] = 174
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 750
                else:
                    xdr['msgType'] = 174
        elif msgType == 0x2006:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS SECURITY MODE COMPLETE')
                xdr['msgType'] = 751
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS SECURITY MODE COMPLETE')
                xdr['msgType'] = 156
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 751
                else:
                    xdr['msgType'] = 156
        elif msgType == 0x2007:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS DATA VOLUME REPORT')
                xdr['msgType'] = 752
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS DATA VOLUME REPORT')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 752
        elif msgType == 0x2009:
            xdr['dir'] = '0'
            if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
                xdr['dir'] = '1'
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS RESET ACKNOWLEDGE')
                xdr['msgType'] = 753
                xdr['dir'] = '1'
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS RESET ACKNOWLEDGE')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '1'
            elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RESET ACKNOWLEDGE')
                xdr['msgType'] = 753
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RESET ACKNOWLEDGE')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '0'
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 753
        elif msgType == 0x201B:
            xdr['dir'] = '0'
            if xdr['sip'][0] in ipRAN or xdr['opc'] in pcRAN:
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipRAN or xdr['dpc'] in pcRAN:
                xdr['dir'] = '1'
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS RESET RESOURCE ACKNOWLEDGE')
                xdr['msgType'] = 754
                xdr['dir'] = '1'
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS RESET RESOURCE ACKNOWLEDGE')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '1'
            elif xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RESET RESOURCE ACKNOWLEDGE')
                xdr['msgType'] = 754
                xdr['dir'] = '0'
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RESET RESOURCE ACKNOWLEDGE')
                # xdr['msgType'] = 
                return
                xdr['dir'] = '0'
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 754
        elif msgType == 0x201E:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS LOCATION RELATED DATA RESPONSE')
                xdr['msgType'] = 755
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS LOCATION RELATED DATA RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 755
        elif msgType == 0x201F:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS INFORMATION TRANSFER CONFIRMATION')
                xdr['msgType'] = 756
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS INFORMATION TRANSFER CONFIRMATION')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 756
        elif msgType == 0x2021:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS UPLINK INFORMATION EXCHANGE RESPONSE')
                xdr['msgType'] = 757
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS UPLINK INFORMATION EXCHANGE RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 757
        elif msgType == 0x2023:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS SESSION START RESPONSE')
                xdr['msgType'] = 758
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS SESSION START RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 758
        elif msgType == 0x2024:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS SESSION UPDATE RESPONSE')
                xdr['msgType'] = 759
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS SESSION UPDATE RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 759
        elif msgType == 0x2025:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS SESSION STOP RESPONSE')
                xdr['msgType'] = 760
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS SESSION STOP RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 760
        elif msgType == 0x2026:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS UE LINKING RESPONSE')
                xdr['msgType'] = 761
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS UE LINKING RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 761
        elif msgType == 0x2027:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS REGISTRATION RESPONSE')
                xdr['msgType'] = 762
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS REGISTRATION RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 762
        elif msgType == 0x2028:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS CN DE-REGISTRATION RESPONSE')
                xdr['msgType'] = 763
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS CN DE-REGISTRATION RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 763
        elif msgType == 0x202A:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS RAB RELEASE')
                xdr['msgType'] = 764
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS RAB RELEASE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 764
        elif msgType == 0x202B:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS ENHANCED RELOCATION COMPLETE RESPONSE')
                xdr['msgType'] = 765
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS ENHANCED RELOCATION COMPLETE RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 765
        elif msgType == 0x202D:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RANAP ENHANCED RELOCATION INFORMATION RESPONSE')
                xdr['msgType'] = 766
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RANAP ENHANCED RELOCATION INFORMATION RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 766
        elif msgType == 0x202E:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS SRVCC CS KEYS RESPONSE')
                xdr['msgType'] = 767
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS SRVCC CS KEYS RESPONSE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 767
        elif msgType == 0x6000:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RAB ASSIGNMENT RESPONSE x N (N>=1)')
                xdr['msgType'] = 768
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RAB ASSIGNMENT RESPONSE x N (N>=1)')
                xdr['msgType'] = 143
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 768
                else:
                    xdr['msgType'] = 143
        elif msgType == 0x4002:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS RELOCATION PREPARATION FAILURE')
                xdr['msgType'] = 769
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS RELOCATION PREPARATION FAILURE')
                xdr['msgType'] = 153
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 769
                else:
                    xdr['msgType'] = 153
        elif msgType == 0x4003:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS RELOCATION FAILURE')
                xdr['msgType'] = 770
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS RELOCATION FAILURE')
                xdr['msgType'] = 152
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 770
                else:
                    xdr['msgType'] = 152
        elif msgType == 0x4006:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS SECURITY MODE REJECT')
                xdr['msgType'] = 771
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS SECURITY MODE REJECT')
                xdr['msgType'] = 157
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 771
                else:
                    xdr['msgType'] = 157
        elif msgType == 0x401E:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS LOCATION RELATED DATA FAILURE')
                xdr['msgType'] = 772
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS LOCATION RELATED DATA FAILURE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 772
        elif msgType == 0x401F:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS INFORMATION TRANSFER FAILURE')
                xdr['msgType'] = 773
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS INFORMATION TRANSFER FAILURE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 773
        elif msgType == 0x4021:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS UPLINK INFORMATION EXCHANGE FAILURE')
                xdr['msgType'] = 774
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS UPLINK INFORMATION EXCHANGE FAILURE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 774
        elif msgType == 0x4023:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS SESSION START FAILURE')
                xdr['msgType'] = 775
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS SESSION START FAILURE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 775
        elif msgType == 0x4024:
            xdr['dir'] = '0'
            if xdr['sip'][0] not in ipRAN: ipRAN.append(xdr['sip'][0])
            if xdr['opc'] not in pcRAN: pcRAN.append(xdr['opc'])
            if xdr['dip'][0] in ipMSC or xdr['dpc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS SESSION UPDATE FAILURE')
                xdr['msgType'] = 776
            elif xdr['dip'][0] in ipSGSN or xdr['dpc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS SESSION UPDATE FAILURE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 776
        elif msgType == 0x4027:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS REGISTRATION FAILURE')
                xdr['msgType'] = 777
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS REGISTRATION FAILURE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 777
        elif msgType == 0x402A:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS MBMS RAB RELEASE FAILURE')
                xdr['msgType'] = 778
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS MBMS RAB RELEASE FAILURE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 778
        elif msgType == 0x402B:
            xdr['dir'] = '1'
            if xdr['dip'][0] not in ipRAN: ipRAN.append(xdr['dip'][0])
            if xdr['dpc'] not in pcRAN: pcRAN.append(xdr['dpc'])
            if xdr['sip'][0] in ipMSC or xdr['opc'] in pcMSC:
                print(xdr['display'], 'IuCS ENHANCED RELOCATION COMPLETE FAILURE')
                xdr['msgType'] = 779
            elif xdr['sip'][0] in ipSGSN or xdr['opc'] in pcSGSN:
                print(xdr['display'], 'IuPS ENHANCED RELOCATION COMPLETE FAILURE')
                # xdr['msgType'] = 
                return
            else:
                if defaultInterface == 'CS':
                    xdr['msgType'] = 779

        outputRANAPXDR(xdr)
    return

def outputBSSAPXDR(xdr):
    global bssapOutputFile,bssapCPLatencyOutputFile
    if xdr['imsi'] == '0': xdr['imsi'] = str(888880000000000+int(xdr['sport'])+int(xdr['dport']))
    if xdr['msgType'] != 0:
        string = pcap.strinfo.sub('8',xdr['imsi'])+'|'+str(xdr['pt_tsn'])+'|'+str(xdr['cgi'])+'|'+str(xdr['Network'])+'|'+pcap.printTime(xdr['ts'])+'|'+str(xdr['dir'])+'|'+str(xdr['msgType'])+'|'+str(xdr['xType'])+'|'+str(xdr['Cause'])+'|'+str(xdr['intValue'])+'|'+xdr['strValue']+'|'+''.join(['{:02x}'.format(x) for x in b''.join([x+b"\x00"*(1600-len(x)) for x in xdr['RawData'][:-1]])+xdr['RawData'][-1]])+'\n'
        ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'),xdr['ts'][1])
        if len(xdr['sip'][-1]) == 4:
            sip = inet_ntoa(xdr['sip'][-1])
            dip = inet_ntoa(xdr['dip'][-1])
        elif len(xdr['sip'][-1]) == 16:
            sip = inet_ntop(AF_INET6, xdr['sip'][-1])
            dip = inet_ntop(AF_INET6, xdr['dip'][-1])
        xdr['interface'] = 'A'
        if(xdr['imsi'] == '0'): xdr['imsi'] = ''
        if(xdr['msisdn'] == '0'): xdr['msisdn'] = ''
        status.file_mode_xdr.append('|'.join([xdr['id'],ts,xdr['imsi'],xdr['msisdn'],sip,str(xdr['sport1']),dip,str(xdr['dport1']),str(xdr['cgi']),xdr['interface'],'',str(xdr['dir']),str(xdr['Cause']),'',str(xdr['msgType']),'','','','','','','',xdr['strValue'],'PC-'+str(xdr['opc']),'PC-'+str(xdr['dpc']),'','',"".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))

        if bssapOutputFile == None:
            a = pcap.printTime(xdr['ts'])
            b = a[0:4]+a[5:7]+a[8:10]+a[11:13]+a[14:16]
            bssapOutputFileName = os.path.join(status.sdlDirectory, 'ImsCP_A_Msg_'+b+'.tmp')
            bssapOutputFile = open(bssapOutputFileName,'w')
            if bssapOutputFile == None:
                exit(-1)
            else:
                status.outputFileList.append(bssapOutputFile)
        bssapOutputFile.writelines(string)
    return

sccpFragList = {}     # opc,dpc,MessageType,DestinationLocalReference

ipMSC = []
ipRAN = []
pcMSC = []
pcRAN = []
ipSGSN = []
pcSGSN = []
cicMSC = {}


pceMSC = []
pcGMSC = []
pcMGCF = []
ipPC = []
ipeMSC = []
ipGMSC = []
ipMGCF = []


ranapXDR = []

biccXDR = []
biccOutputFile = None
biccCPLatencyOutputFile = None

mcOutputFile = None
mcCPLatencyOutputFile = None

gprsOutputFile = None
gprsCPLatencyOutputFile = None

ranapOutputFile = None
ranapCPLatencyOutputFile = None

bssapOutputFile = None
bssapCPLatencyOutputFile = None

mcOutputFile = None
mcCPLatencyOutputFile = None

gprsMM = {}
gprsMM[1] = 112 # ATTACH_REQUEST
gprsMM[2] = 113 # ATTACH_ACCEPT
gprsMM[3] = 114 # ATTACH_COMPLETE
gprsMM[4] = 115 # ATTACH_REJECT
gprsMM[5] = 120 # DETACH_REQUEST
gprsMM[6] = 121 # DETACH_ACCEPT
gprsMM[8] = 124 # RAU_REQUEST
gprsMM[9] = 125 # RAU_ACCEPT
gprsMM[10] = 126 # RAU_COMPLETE
gprsMM[11] = 127 # RAU_REJECT
gprsMM[12] = 128 # SERVICE_REQUEST
gprsMM[13] = 129 # SERVICE_ACCEPT
gprsMM[14] = 130 # SERVICE_REJECT
gprsMM[18] = 116 # AUTH_AND_CIPHERING_REQUEST
gprsMM[19] = 117 # AUTH_AND_CIPHERING_RESPONSE
gprsMM[20] = 118 # AUTH_AND_CIPHERING_REJECT
gprsMM[28] = 119 # AUTH_AND_CIPHERING_FAILURE
gprsMM[21] = 122 # IDENTITY_REQUEST
gprsMM[22] = 123 # IDENTITY_RESPONSE

gprsSM = {}
gprsSM[65] = 161 # ACTIVATE_PDP_CONTEXT_REQUEST
gprsSM[66] = 162 # ACTIVATE_PDP_CONTEXT_ACCEPT
gprsSM[67] = 163 # ACTIVATE_PDP_CONTEXT_REJECT
gprsSM[68] = 171 # REQUEST_PDP_CONTEXT_ACTIVATION
gprsSM[69] = 172 # REQUEST_PDP_CONTEXT_ACTIVATION_REJECT
gprsSM[70] = 164 # DEACTIVATE_PDP_CONTEXT_REQUEST
gprsSM[71] = 165 # DEACTIVATE_PDP_CONTEXT_ACCEPT
gprsSM[72] = 167 # MODIFY_PDP_CONTEXT_REQUEST(DL)
gprsSM[73] = 169 # MODIFY_PDP_CONTEXT_ACCEPT(DL)
gprsSM[74] = 166 # MODIFY_PDP_CONTEXT_REQUEST(UL)
gprsSM[75] = 168 # MODIFY_PDP_CONTEXT_ACCEPT(UL)
gprsSM[76] = 170 # MODIFY_PDP_CONTEXT_REJECT
gprsSM[77] = 158 # ACTIVATE_2nd_PDP_CONTEXT_REQUEST
gprsSM[78] = 159 # ACTIVATE_2nd_PDP_CONTEXT_ACCEPT
gprsSM[79] = 160 # ACTIVATE_2nd_PDP_CONTEXT_REJECT


mcMM = {}
mcMM[1] = 420
mcMM[2] = 421
mcMM[4] = 422
mcMM[8] = 423
mcMM[17] = 402
mcMM[18] = 403
mcMM[20] = 404
mcMM[28] = 401
mcMM[24] = 418
mcMM[25] = 419
mcMM[33] = 408
mcMM[34] = 409
mcMM[35] = 407
mcMM[36] = 410
mcMM[40] = 406
mcMM[26] = 431 # 'TMSI REALLOCATION COMMAND'
mcMM[27] = 432 # 'TMSI REALLOCATION COMPLETE'
mcMM[37] = 433 # 'CM SERVICE PROMPT'
mcMM[41] = 434 # 'ABORT'
mcMM[48] = 455 # 'MM NULL'
mcMM[49] = 456 # 'MM STATUS'
mcMM[50] = 457 # 'MM INFORMATION'

mcCC = {}
mcCC[1] = 400
mcCC[8] = 405
mcCC[7] = 411
mcCC[15] = 412
mcCC[14] = 414
mcCC[5] = 430
mcCC[24] = 415
mcCC[25] = 416
mcCC[26] = 417
mcCC[28] = 427
mcCC[29] = 428
mcCC[30] = 429
mcCC[37] = 413
mcCC[45] = 425
mcCC[42] = 426
mcCC[2] = 435 # 'CALL PROCEEDING'
mcCC[3] = 436 # 'PROGRESS'
mcCC[4] = 437 # 'CC-ESTABLISHMENT'
mcCC[6] = 438 # 'CC-ESTABLISHMENT CONFIRMED'
mcCC[11] = 439 # 'RECALL'
mcCC[9] = 440 # 'START CC'
mcCC[23] = 441 # 'MODIFY'
mcCC[31] = 442 # 'MODIFY COMPLETE'
mcCC[19] = 443 # 'MODIFY REJECT'
mcCC[16] = 444 # 'USER INFORMATION'
mcCC[57] = 445 # 'CONGESTION CONTROL'
mcCC[62] = 446 # 'NOTIFY'
mcCC[61] = 447 # 'STATUS'
mcCC[52] = 448 # 'STATUS ENQUIRY'
mcCC[53] = 449 # 'START DTMF'
mcCC[49] = 450 # 'STOP DTMF'
mcCC[50] = 451 # 'STOP DTMF ACKNOWLEDGE'
mcCC[54] = 452 # 'START DTMF ACKNOWLEDGE'
mcCC[55] = 453 # 'START DTMF REJECT'
mcCC[58] = 454 # 'FACILITY'

ranap = {}
ranap[0x0001] = 700  # IU RELEASE COMMAND
ranap[0x0002] = 701  # RELOCATION REQUIRED
ranap[0x0003] = 702  # RELOCATION REQUEST
ranap[0x0004] = 703  # RELOCATION CANCEL
ranap[0x0005] = 704  # SRNS CONTEXT REQUEST
ranap[0x0006] = 705  # SECURITY MODE COMMAND
ranap[0x0007] = 706  # DATA VOLUME REPORT REQUEST
ranap[0x0009] = 707  # RESET
ranap[0x001B] = 708  # RESET RESOURCE
ranap[0x001E] = 709  # LOCATION RELATED DATA REQUEST
ranap[0x001F] = 710  # INFORMATION TRANSFER INDICATION
ranap[0x0021] = 711  # UPLINK INFORMATION EXCHANGE REQUEST
ranap[0x0023] = 712  # MBMS SESSION START
ranap[0x0024] = 713  # MBMS SESSION UPDATE
ranap[0x0025] = 714  # MBMS SESSION STOP REQUEST
ranap[0x0026] = 715  # MBMS UE LINKING REQUEST
ranap[0x0027] = 716  # MBMS REGISTRATION REQUEST
ranap[0x0028] = 717  # MBMS CN DE-REGISTRATION REQUEST
ranap[0x002A] = 718  # MBMS RAB RELEASE REQUEST
ranap[0x002B] = 719  # ENHANCED RELOCATION COMPLETE REQUEST
ranap[0x002D] = 720  # RANAP ENHANCED RELOCATION INFORMATION REQUEST
ranap[0x002E] = 721  # SRVCC CS KEYS REQUEST
ranap[0x001D] = 722  # RAB MODIFY REQUEST
ranap[0x000A] = 723  # RAB RELEASE REQUEST
ranap[0x000B] = 724  # IU RELEASE REQUEST
ranap[0x000C] = 725  # RELOCATION DETECT
ranap[0x000D] = 726  # RELOCATION COMPLETE
ranap[0x001C] = 727  # RANAP RELOCATION INFORMATION
ranap[0x0017] = 728  # SRNS DATA FORWARD COMMAND
ranap[0x0018] = 729  # FORWARD SRNS CONTEXT
# ranap[0x0018] = 730  # FORWARD SRNS CONTEXT
ranap[0x000E] = 731  # PAGING
ranap[0x000F] = 732  # COMMON ID
ranap[0x0010] = 733  # CN INVOKE TRACE
ranap[0x001A] = 734  # CN DEACTIVATE TRACE
ranap[0x0011] = 735  # LOCATION REPORTING CONTROL
ranap[0x0012] = 736  # LOCATION REPORT
ranap[0x0013] = 737  # INITIAL UE MESSAGE
ranap[0x0014] = 738  # DIRECT TRANSFER
ranap[0x0015] = 739  # OVERLOAD
ranap[0x0016] = 740  # ERROR INDICATION
ranap[0x0020] = 741  # UE SPECIFIC INFORMATION INDICATION
ranap[0x0022] = 742  # DIRECT INFORMATION TRANSFER
ranap[0x0029] = 743  # MBMS RAB ESTABLISHMENT INDICATION
ranap[0x002C] = 744  # ENHANCED RELOCATION COMPLETE CONFIRM
ranap[0x0000] = 745  # RAB ASSIGNMENT REQUEST
ranap[0x2001] = 746  # IU RELEASE COMPLETE
ranap[0x2002] = 747  # RELOCATION COMMAND
ranap[0x2003] = 748  # RELOCATION REQUEST ACKNOWLEDGE
ranap[0x2004] = 749  # RELOCATION CANCEL ACKNOWLEDGE
ranap[0x2005] = 750  # SRNS CONTEXT RESPONSE
ranap[0x2006] = 751  # SECURITY MODE COMPLETE
ranap[0x2007] = 752  # DATA VOLUME REPORT
ranap[0x2009] = 753  # RESET ACKNOWLEDGE
ranap[0x201B] = 754  # RESET RESOURCE ACKNOWLEDGE
ranap[0x201E] = 755  # LOCATION RELATED DATA RESPONSE
ranap[0x201F] = 756  # INFORMATION TRANSFER CONFIRMATION
ranap[0x2021] = 757  # UPLINK INFORMATION EXCHANGE RESPONSE
ranap[0x2023] = 758  # MBMS SESSION START RESPONSE
ranap[0x2024] = 759  # MBMS SESSION UPDATE RESPONSE
ranap[0x2025] = 760  # MBMS SESSION STOP RESPONSE
ranap[0x2026] = 761  # MBMS UE LINKING RESPONSE
ranap[0x2027] = 762  # MBMS REGISTRATION RESPONSE
ranap[0x2028] = 763  # MBMS CN DE-REGISTRATION RESPONSE
ranap[0x202A] = 764  # MBMS RAB RELEASE
ranap[0x202B] = 765  # ENHANCED RELOCATION COMPLETE RESPONSE
ranap[0x202D] = 766  # RANAP ENHANCED RELOCATION INFORMATION RESPONSE
ranap[0x202E] = 767  # SRVCC CS KEYS RESPONSE
ranap[0x6000] = 768  # RAB ASSIGNMENT RESPONSE x N (N>=1)
ranap[0x4002] = 769  # RELOCATION PREPARATION FAILURE
ranap[0x4003] = 770  # RELOCATION FAILURE
ranap[0x4006] = 771  # SECURITY MODE REJECT
ranap[0x401E] = 772  # LOCATION RELATED DATA FAILURE
ranap[0x401F] = 773  # INFORMATION TRANSFER FAILURE
ranap[0x4021] = 774  # UPLINK INFORMATION EXCHANGE FAILURE
ranap[0x4023] = 775  # MBMS SESSION START FAILURE
ranap[0x4024] = 776  # MBMS SESSION UPDATE FAILURE
ranap[0x4027] = 777  # MBMS REGISTRATION FAILURE
ranap[0x402A] = 778  # MBMS RAB RELEASE FAILURE
ranap[0x402B] = 779  # ENHANCED RELOCATION COMPLETE FAILURE

ProtocolDiscriminator = {}
ProtocolDiscriminator[0] = 'group call control'
ProtocolDiscriminator[1] = 'broadcast call control'
ProtocolDiscriminator[2] = 'EPS session management messages'
ProtocolDiscriminator[3] = 'call control; call related SS messages'
ProtocolDiscriminator[4] = 'GPRS Transparent Transport Protocol (GTTP)'
ProtocolDiscriminator[5] = 'mobility management messages'
ProtocolDiscriminator[6] = 'radio resources management messages'
ProtocolDiscriminator[7] = 'EPS mobility management messages'
ProtocolDiscriminator[8] = 'GPRS mobility management messages'
ProtocolDiscriminator[9] = 'SMS messages'
ProtocolDiscriminator[10] = 'GPRS session management messages'
ProtocolDiscriminator[11] = 'non call related SS messages'
ProtocolDiscriminator[12] = 'Location services specified in 3GPP TS 44.071 [8a]'
ProtocolDiscriminator[14] = 'reserved'
ProtocolDiscriminator[15] = 'tests'

bssmap = {}
bssmap[1] = 1100   # ASSIGNMENT REQUEST
bssmap[2] = 1101   # ASSIGNMENT COMPLETE
bssmap[3] = 1102   # ASSIGNMENT FAILURE
bssmap[8] = 1103   # CHANNEL MODIFY REQUEST
bssmap[16] = 1104   # HANDOVER REQUEST
bssmap[17] = 1105   # HANDOVER REQUIRED
bssmap[18] = 1106   # HANDOVER REQUEST ACKNOWLEDGE
bssmap[19] = 1107   # HANDOVER COMMAND
bssmap[20] = 1108   # HANDOVER COMPLETE
bssmap[21] = 1109   # HANDOVER SUCCEEDED
bssmap[22] = 1110   # HANDOVER FAILURE
bssmap[23] = 1111   # HANDOVER PERFORMED
bssmap[24] = 1112   # HANDOVER CANDIDATE ENQUIRE
bssmap[25] = 1113   # HANDOVER CANDIDATE RESPONSE
bssmap[26] = 1114   # HANDOVER REQUIRED REJECT
bssmap[27] = 1115   # HANDOVER DETECT
bssmap[112] = 1116   # INTERNAL HANDOVER REQUIRED
bssmap[113] = 1117   # INTERNAL HANDOVER REQUIRED REJECT
bssmap[114] = 1118   # INTERNAL HANDOVER COMMAND
bssmap[115] = 1119   # INTERNAL HANDOVER ENQUIRY
bssmap[32] = 1163   # CLEAR COMMAND
bssmap[33] = 1164   # CLEAR COMPLETE
bssmap[34] = 1165   # CLEAR REQUEST
bssmap[40] = 1120   # SUSPEND
bssmap[41] = 1121   # RESUME
bssmap[43] = 1122   # PERFORM LOCATION REQUEST
bssmap[44] = 1123   # LSA INFORMATION
bssmap[45] = 1124   # PERFORM LOCATION RESPONSE
bssmap[46] = 1125   # PERFORM LOCATION ABORT
bssmap[47] = 1126   # COMMON ID
bssmap[120] = 1127   # REROUTE COMMAND
bssmap[121] = 1128   # REROUTE COMPLETE
bssmap[58] = 1129   # CONNECTIONLESS INFORMATION
bssmap[80] = 1130   # RESOURCE REQUEST
bssmap[81] = 1131   # RESOURCE INDICATION
bssmap[82] = 1132   # PAGING
bssmap[83] = 1133   # CIPHER MODE COMMAND
bssmap[84] = 1134   # CLASSMARK UPDATE
bssmap[85] = 1135   # CIPHER MODE COMPLETE
bssmap[86] = 1136   # QUEUING INDICATION
bssmap[87] = 1137   # COMPLETE LAYER 3 INFORMATION
bssmap[88] = 1138   # CLASSMARK REQUEST
bssmap[89] = 1139   # CIPHER MODE REJECT
bssmap[4] = 1140   # VGCS/VBS SETUP
bssmap[5] = 1141   # VGCS/VBS SETUP ACK
bssmap[6] = 1142   # VGCS/VBS SETUP REFUSE
bssmap[7] = 1143   # VGCS/VBS ASSIGNMENT REQUEST
bssmap[28] = 1144   # VGCS/VBS ASSIGNMENT RESULT
bssmap[29] = 1145   # VGCS/VBS ASSIGNMENT FAILURE
bssmap[30] = 1146   # VGCS/VBS QUEUING INDICATION
bssmap[59] = 1147   # VGCS/VBS ASSIGNMENT STATUS
bssmap[60] = 1148   # VGCS/VBS AREA CELL INFO
bssmap[31] = 1149   # UPLINK REQUEST
bssmap[39] = 1150   # UPLINK REQUEST ACKNOWLEDGE
bssmap[73] = 1151   # UPLINK REQUEST CONFIRMATION
bssmap[74] = 1152   # UPLINK RELEASE INDICATION
bssmap[75] = 1153   # UPLINK REJECT COMMAND
bssmap[76] = 1154   # UPLINK RELEASE COMMAND
bssmap[77] = 1155   # UPLINK SEIZED COMMAND
bssmap[96] = 1156   # VGCS ADDITIONAL INFORMATION
bssmap[97] = 1157   # VGCS SMS
bssmap[98] = 1158   # NOTIFICATION DATA
bssmap[99] = 1159   # UPLINK APPLICATION DATA
bssmap[116] = 1160  # LCLS-CONNECT-CONTROL
bssmap[117] = 1161  # LCLS-CONNECT-CONTROL-ACK
bssmap[118] = 1162  # LCLS-NOTIFICATION

biccMsg1 = {}
biccMsg1[1] = 'IAM(Initial Address)'             # Initial Address Initial Address
biccMsg1[2] = 'SAM(Subsequent Address)'          # Subsequent Address Subsequent Address
biccMsg1[3] = 'INR(Information Request)'         # Information Request Information Request
biccMsg1[4] = 'INF(Information)'                 # Information Information
biccMsg1[5] = 'COT(Continuity)'                  # Continuity Continuity
biccMsg1[6] = 'ACM(Address Complete)'            # Address Complete Address Complete
biccMsg1[7] = 'CON(Connect)'                     # Connect Connect
biccMsg1[8] = 'FOT(Forward Transfer)'            # Forward Transfer Forward Transfer
biccMsg1[9] = 'ANM(Answer)'                      # Answer Answer
biccMsg1[12] = 'REL(Release)'                    # Release Release
biccMsg1[13] = 'SUS(Suspend)'                    # Suspend Suspend
biccMsg1[14] = 'RES(Resume)'                     # Resume Resume
biccMsg1[16] = 'RLC(Release Complete)'           # Release Complete Release Complete
biccMsg1[31] = 'FAR(Facility Requesst)'          # Facility Requesst Facility Requesst
biccMsg1[32] = 'FAA(Facility Accepted)'          # Facility Accepted Facility Accepted
biccMsg1[33] = 'FRJ(Facility Reject)'            # Facility Reject Facility Reject
biccMsg1[44] = 'CPG(Call Progress)'              # Call Progress Call Progress
biccMsg1[45] = 'UUS(User-to-User Information)'   # User-to-User Information User-to-User Information
biccMsg1[47] = 'CFN(Confusion)'                  # Confusion Confusion
biccMsg1[51] = 'FAC(Facility)'                   # Facility Facility
biccMsg1[54] = 'IDR(Identification Request)'     # Identification Request Identification Request
biccMsg1[55] = 'IDS(Identification Response)'    # Identification Response Identification Response
biccMsg1[56] = 'SGM(Segmentation)'               # Segmentation Segmentation
biccMsg1[65] = 'APM(Application Transport)'      # Application Transport Application Transport

biccMsg = {}
biccMsg[1] = 1200  # Initial Address Initial Address
biccMsg[2] = 1201  # Subsequent Address Subsequent Address
biccMsg[3] = 1202  # Information Request Information Request
biccMsg[4] = 1203  # Information Information
biccMsg[5] = 1204  # Continuity Continuity
biccMsg[6] = 1205  # Address Complete Address Complete
biccMsg[7] = 1206  # Connect Connect
biccMsg[8] = 1207  # Forward Transfer Forward Transfer
biccMsg[9] = 1208  # Answer Answer
biccMsg[12] = 1209  # Release Release
biccMsg[13] = 1210  # Suspend Suspend
biccMsg[14] = 1211  # Resume Resume
biccMsg[16] = 1212  # Release Complete Release Complete
biccMsg[31] = 1213  # Facility Requesst Facility Requesst
biccMsg[32] = 1214  # Facility Accepted Facility Accepted
biccMsg[33] = 1215  # Facility Reject Facility Reject
biccMsg[44] = 1216  # Call Progress Call Progress
biccMsg[45] = 1217  # User-to-User Information User-to-User Information
biccMsg[47] = 1218  # Confusion Confusion
biccMsg[51] = 1219  # Facility Facility
biccMsg[54] = 1220  # Identification Request Identification Request
biccMsg[55] = 1221  # Identification Response Identification Response
biccMsg[56] = 1222  # Segmentation Segmentation
biccMsg[65] = 1223  # Application Transport Application Transport

