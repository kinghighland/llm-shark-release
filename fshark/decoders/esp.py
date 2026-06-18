import sys
import os
import struct
import base64
import datetime
from collections import Counter
import pcap
import sctp
import tcp
import udp
import re
from string import printable

p = [x for x in printable.encode()]

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


def decodeESP(xdr,raw,flush):
    xdr['esp'] = True
    if(flush):
        m = re.search(r'ACK|BYE|CANCEL|INFO|INVITE|MESSAGE|NOTIFY|OPTIONS|PRACK|REFER|REGISTER|SUBSCRIBE|UPDATE|SIP',to_string(raw))
        if(m.span()[0] == 16):
            udp.decodeUDP(xdr,raw[8:])
        else:
            tcp.decodeTCP(xdr,raw[8:])
    else:
        if len(raw) < 30:
            print('id =',xdr['id'],'not a esp packet')
            del xdr
            return
        spi,seq,padLength,nextHeader,auth = struct.unpack('!2I2B12s',raw[0:8]+raw[-14:])

        ipAddressLength = len(xdr['sip'][-1])

        if ipAddressLength == 4:
            if nextHeader >128:
                print('Bad ESP packet',xdr['id'])
                del xdr,raw
                return
        elif ipAddressLength == 16:
            if nextHeader >128:
                print('Bad ESP packet',xdr['id'])
                del xdr,raw
                return
        else:
            print('ipaddress length is not 4 or 16',ipAddressLength)
            del xdr,raw
            return

        if nextHeader == 17:
            udp.decodeUDP(xdr,raw[8:-14-padLength])
        elif nextHeader == 6:
            tcp.decodeTCP(xdr,raw[8:-14-padLength])
        return