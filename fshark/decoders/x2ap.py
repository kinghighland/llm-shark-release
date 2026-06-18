import sys
import os
import struct
import base64
import datetime
from collections import Counter

def decodeX2AP(xdr,raw,flush):
    xdr['display'] += ', X2AP'
    xdr['Level'] += 1
    print(xdr['display'])
    return

    sport,dport,vTag,crc = struct.unpack('!2HII',raw[:12])
    chucks = []
    i = 0
    while i < len(raw)-16:
        chuckType,chuckFlags,chuckLength = struct.unpack('!BBH',raw[12+i:12+i+4])
        if chuckType == 0:
            try:
                TSN,streamID,streamSeq,payloadID = struct.unpack('!IHHI',raw[12+i+4:12+i+4+12])
                payload = raw[12+i+4+12:12+i+4+chuckLength]
                chuck = (chuckType,chuckFlags,chuckLength,TSN,streamID,streamSeq,payloadID,payload)
                chucks.append(chuck)
            except:
                break
        i += ((chuckLength+3)//4)*4
    for chuck in chucks:
        xdr1 = xdr.copy()
        if chuck[6] == 27:                          # payloadID, 27 = X2AP
            pass
    return

x2apDict = {}
x2apDict[b'0000']='HandoverRequest'
x2apDict[b'2000']='HandoverRequestAcknowledge'
x2apDict[b'4000']='HandoverPreparationFailure'
x2apDict[b'0001']='HandoverCancel'
x2apDict[b'0002']='LoadInformation'
x2apDict[b'0003']='ErrorIndication'
x2apDict[b'0004']='SNStatusTransfer'
x2apDict[b'0005']='UEContextRelease'
x2apDict[b'0006']='X2SetupRequest'
x2apDict[b'2006']='X2SetupResponse'
x2apDict[b'4006']='X2SetupFailure'
x2apDict[b'0007']='ResetRequest'
x2apDict[b'2007']='ResetResponse'
x2apDict[b'0008']='ENBConfigurationUpdate'
x2apDict[b'2008']='ENBConfigurationUpdateAcknowledge'
x2apDict[b'4008']='ENBConfigurationUpdateFailure'
x2apDict[b'0009']='ResourceStatusRequest'
x2apDict[b'2009']='ResourceStatusResponse'
x2apDict[b'4009']='ResourceStatusFailure'
x2apDict[b'000A']='ResourceStatusUpdate'
x2apDict[b'000B']='PrivateMessage'
x2apDict[b'000C']='MobilityChangeRequest'
x2apDict[b'200C']='MobilityChangeAcknowledge'
x2apDict[b'400C']='MobilityChangeFailure'
x2apDict[b'000D']='RLFIndication'
x2apDict[b'000E']='HandoverReport'
x2apDict[b'000F']='CellActivationRequest'
x2apDict[b'200F']='CellActivationResponse'
x2apDict[b'400F']='CellActivationFailure'
x2apDict[b'0010']='X2Release'
x2apDict[b'0011']='X2MessageTransfer'