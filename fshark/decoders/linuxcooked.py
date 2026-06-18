import sys
import os
import struct
import base64
import datetime
import pcap
import ip

def decodeLinuxcooked(xdr,raw):
    xdr['display'] += ', Linux Cooked Capture'
    xdr['Level'] += 1

    xdr['RawData'][0] = raw[16:]
    i = 14
    bytes = struct.unpack('!H',raw[i:i+2])[0]
    i += 2
    if bytes == 2048:                        # 0x0800, IPv4
        ip.decodeIPv4(xdr,raw[i:])
    elif bytes == 34525:                     # 0x86DD, IPv6
        ip.decodeIPv6(xdr,raw[i:])
    elif bytes <= 1500:                      # less than 1500, max size of ethernet
        #print('Linuxcooked type and length:',bytes)
        pass
    elif bytes == 33024:                     # 33024,0x8100
        i = 18
        m = struct.unpack('!H',raw[i:i+2])[0]
        if m == 2048:
            ip.decodeIPv4(xdr,raw[i+2:])
        elif m == 34525:
            ip.decodeIPv6(xdr,raw[i+2:])
    elif bytes == 33079:                     # 33079,0x8137, IPX/SPX
        #print('Linuxcooked, IPX/SPX')
        pass
    elif bytes == 2054:                      # 2054 ,0x0806, ARP
        #print('Linuxcooked, ARP')
        pass
    elif bytes == 34825:                     # 34825 ,0x8809, Slow Protocols
        #print('Linuxcooked, Slow Protocols')
        pass    
    elif bytes == 34917:                     # 34917 ,0x8865, unknown
        #print('Linuxcooked, unknown')
        pass
    elif bytes == 35020:                     # 35020 ,0x88cc, 802.1 Link Layer Discovery Protocol (LLDP)
        #print('Linuxcooked, unknown')
        pass
    else:
        print('Linuxcooked: ',bytes)
    return None
