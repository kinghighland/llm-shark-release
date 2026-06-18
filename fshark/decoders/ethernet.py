import sys
import os
import struct
import base64
import datetime
import pcap
import ip

def decodeEthernet(xdr,raw):
    xdr['display'] += ', Ethernet'
    xdr['Level'] += 1
    ethnetDestinationAddressHeader = struct.unpack('!2s',raw[:2])[0]
    if ethnetDestinationAddressHeader == b'33':
        print(xdr['display'],' IPv6 Multi-cast Ethernet header 0x0303')
        del xdr,raw
        return
    if ethnetDestinationAddressHeader[0] == 1:
        print(xdr['display'],' Ethernet Multi-cast header 0x01')
        del xdr,raw
        return
    i = 12

    while(i < len(raw)):
        bytes = struct.unpack('!H',raw[i:i+2])[0]
        if bytes == 33024:                       # 0x8100, vlan
            i += 4
        else:
            i += 2
            xdr['RawData'][0] = raw[i:]
            break

    if bytes == 2048:                        # 0x0800, IPv4
        ip.decodeIPv4(xdr,raw[i:])
        pass
    elif bytes == 34525:                     # 0x86DD, IPv6
        ip.decodeIPv6(xdr,raw[i:])
        pass
    elif bytes <= 1500:                      # less than 1500, max size of ethernet
        print('ethernet type and length:',bytes)
        pass
    elif bytes == 33079:                     # 33079,0x8137, IPX/SPX
        print('ethernet, IPX/SPX')
        pass
    elif bytes == 2054:                      # 2054 ,0x0806, ARP
        print('ethernet, ARP')
        pass
    elif bytes == 32922:                     # 32922 ,0x809A, IEEE 802.15.4
        print('ethernet, IEEE 802.15.4')
        pass
    elif bytes == 34917:                     # 34917 ,0x8865, unknown
        print('ethernet, unknown')
        pass    
    elif bytes == 34917:                     # 34917 ,0x8865, unknown
        print('ethernet, unknown')
        pass
    elif bytes == 35020:                     # 35020 ,0x88cc, 802.1 Link Layer Discovery Protocol (LLDP)
        print('ethernet, 802.1 Link Layer Discovery Protocol (LLDP)')
        pass
    elif bytes == 48770:                     # 48770 ,0xBE82, Unknown
        print('ethernet, unknown')
        pass
    else:
        print('ethernet: ',bytes)
    return None