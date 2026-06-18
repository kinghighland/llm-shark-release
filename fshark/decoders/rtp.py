import sys
import os
import struct
import base64
import datetime
import time
from collections import Counter
import pcap
import sctp
import tcp
import udp

def decodeRTP(xdr,raw,flush):
    xdr['display'] += ', RTP'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','4'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''
    xdr['ip'] = 0
    
    print(xdr['display'])
    
    del xdr,raw
    pass

def decodeRTCP(xdr,raw,flush):
    xdr['display'] += ', RTCP'
    xdr['Level'] += 1
    xdr['imsi'], xdr['cgi'], xdr['Network'] = '0','0','4'
    xdr['pt_tsn'], xdr['dir'], xdr['msgType'], xdr['xType'] = (xdr['ts'][0]-time.timezone) % 86400 // 3600,0,0,0
    xdr['Cause'], xdr['intValue'], xdr['strValue'] =  0,'',''
    xdr['ip'] = 0
    
    print(xdr['display'])
    
    del xdr,raw
    pass