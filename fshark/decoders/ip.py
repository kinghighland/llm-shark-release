import sys
import os
import struct
import base64
import datetime
import time
import binascii
import pcap
import re
import status
import udp
import tcp
import esp
import sctp
from collections import Counter

IPv4frags_dict = {}

def defragIPv4_dict(id,sip,dip, Level):
    frag_list = IPv4frags_dict.get((sip,dip,Level,id),{})
    # {'xdr': xdr, "offset": flagoffset, "raw": raw[ihl:], "protocol": protocol,'flags':flags, 'length':length}
    if(len(frag_list) == 1):
        return None, None, None
    sorted_frags_list = sorted(frag_list, key = lambda x: x['offset'])

    first = sorted_frags_list[0]
    if(first['flags'] == 1 and first['offset'] == 0):
        last = sorted_frags_list[-1]
        full = sum([x['length'] for x in sorted_frags_list[:-1]])
        if(last['offset'] == full and last['flags'] == 0):
            xdr = first['xdr']
            RawData, RawData1 = [], []
            for temp in sorted_frags_list:
                RawData = RawData + temp['xdr']['RawData']
                RawData1 = RawData1 + temp['xdr']['RawData1']
            xdr['RawData'] = RawData
            xdr['RawData1'] = RawData1
            raw = b''.join([x['raw'] for x in sorted_frags_list])
            protocol = None
            xdr['frags'] = []
            for record in sorted_frags_list:
                if(record['protocol'] != None):
                    protocol = record['protocol']
                    xdr['frags'].append(record['xdr']['id'])
            del IPv4frags_dict[(sip,dip,Level,id)]
            return xdr, raw, protocol
        return None, None, None
    else:
        return None, None, None

def decodeIPv4(xdr,raw):
    # skip ttl, since ttl will be reduced alone with routers.
    raw_no_ttl = raw[:8] + raw[9:10] + raw[12:]
    #raw_no_ttl = raw
    found = status.ipv4_dup_list_1.get((xdr['Level'],raw_no_ttl),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup IPv4 Packet')
            return
        else:
            xdr['dup'] = True
    found = status.ipv4_dup_list_2.get((xdr['Level'],raw_no_ttl),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup IPv4 Packet')
            return
        else:
            xdr['dup'] = True
    found = status.ipv4_dup_list_3.get((xdr['Level'],raw_no_ttl),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup IPv4 Packet')
            return
        else:
            xdr['dup'] = True
    status.ipv4_dup_list_3 = status.ipv4_dup_list_2
    status.ipv4_dup_list_2 = status.ipv4_dup_list_1
    status.ipv4_dup_list_1 = {}
    status.ipv4_dup_list_1[(xdr['Level'],raw_no_ttl)] = xdr['ts']

    xdr['display'] += ', IPv4'
    xdr['Level'] += 1
    header = struct.unpack('!B',raw[:1])[0]
    if (header>>4) == 4:                                      # it is a IPv4 packet
        xdr['IPv6'] = False
        ihl = (header & 15) * 4
        header,tos,length,id,flagsByte,ttl,protocol,CRC,sip,dip = struct.unpack('!2B3H2BH4s4s',raw[:20])
        
        if sip == 0 or sip == 0xFFFFFFFF:
            del xdr
            return
        if dip == 0 or dip == 0xFFFFFFFF:
            del xdr
            return

        xdr['sip'].append(sip)
        xdr['dip'].append(dip)

        flags = (flagsByte>>13)&1
        flagoffset = (flagsByte&((1<<12)-1))*8
        if flags == 1 or flagoffset != 0:
            print(xdr['display'], ' Fragment')
            IPv4frags_dict.setdefault((sip,dip,xdr['Level'],id),[]).append({'xdr': xdr, "offset": flagoffset, "raw": raw[ihl:], "protocol": protocol,'flags':flags,"length":length-ihl})
            xdr,raw,protocol = defragIPv4_dict(id,sip,dip,xdr['Level'])
        else:
            raw = raw[ihl:length]

        if xdr == None:
            #print(' Fragment added')
            pass
        else:
            if protocol  == 1:
                print(xdr['display'], ' ICMP not Decoded')
                pass
            elif protocol  == 2:
                print(xdr['display'], ' IGMP not Decoded')
                pass
            elif protocol  == 6:                 #print(xdr['display'], ' TCP not Decoded')
                if len(raw) == 32:
                    print('tcp length is 0')
                    del xdr
                else:
                    tcp.decodeTCP(xdr,raw)
            elif protocol  == 17:
                #print(xdr['display'], ' UDP not Decoded')
                udp.decodeUDP(xdr,raw)
            elif protocol  == 50:
                #print(xdr['display'], ' ESP not Decoded')
                esp.decodeESP(xdr,raw,False)
                pass
            elif protocol  == 89:
                print(xdr['display'], ' OSPFIGP not Decoded')
                pass
            elif protocol  == 112:
                print(xdr['display'], ' (112) VRRP not Decoded')
                pass
            elif protocol  == 114:
                print(xdr['display'], ' (114)any 0-hop protocol not Decoded')
                pass
            elif protocol  == 132:       # SCTP
                # if len(raw) <= 28:
                #     print('SCTP packet is too small')
                #     return
                sctp.decodeSCTP(xdr,raw)
            else:
                print(xdr['display'], protocol,' not Decoded')
                pass
    else:
        if header>>4 == 13:
            pass
        else:
            print(xdr['display']+', IP version is not 4, it is ',header>>4)
    return

def flushIPv4():
    global IPv4frags_dict
    # copy一份数据，避免报错：dictionary changed size during iteration
    IPv4frags_dict_copy = IPv4frags_dict.copy()
    for session in IPv4frags_dict_copy:
        sorted_ip_frag_list = sorted(IPv4frags_dict_copy[session], key = lambda x: x['offset'])
        temp_list = [[sorted_ip_frag_list[0]]]
        for n in sorted_ip_frag_list[1:]:
            if(temp_list[-1][-1]['offset']+temp_list[-1][-1]['length'] == n['offset']):
                temp_list[-1].append(n)
            else:
                temp_list.append([])
                temp_list[-1].append(n)
        for frag_list in temp_list:
            xdr = frag_list[0]['xdr']
            RawData, RawData1 = [], []
            raw = b''
            for x in frag_list:
                RawData = RawData + x['xdr']['RawData']
                RawData1 = RawData1 + x['xdr']['RawData1']
                raw = raw + x['raw']
            xdr['RawData'] = RawData
            xdr['RawData1'] = RawData1
            xdr['frags'] = [x['xdr']['id'] for x in frag_list]
            
            protocol = frag_list[0]['protocol']
            if(len(raw) != 0):
                if protocol  == 1:
                    print('Frame id:',xdr['id'],xdr['display'], ' ICMP not Decoded')
                    pass
                elif protocol  == 6:
                    print('Frame id:',xdr['id'],xdr['display'])
                    tcp.decodeTCP(xdr,raw)
                elif protocol  == 17:
                    print('Frame id:',xdr['id'],xdr['display'])
                    udp.decodeUDP(xdr,raw)
                elif protocol  == 50:
                    print('Frame id:',xdr['id'],xdr['display'])
                    esp.decodeESP(xdr,raw,False)
                elif protocol  == 89:
                    #print(xdr['display'], ' OSPFIGP not Decoded')
                    pass
                elif protocol  == 112:
                    #print(xdr['display'], ' (112) VRRP not Decoded')
                    pass
                elif protocol  == 114:
                    #print(xdr['display'], ' (114)any 0-hop protocol not Decoded')
                    pass
                elif protocol  == 132:
                    print('Frame id:',xdr['id'],xdr['display'])
                    # sctp.decodeSCTP(frag['xdr'],raw)
                    sctp.decodeSCTP(xdr,raw)
                    pass
                else:
                    print('Frame id:',xdr['id'],xdr['display'], protocol,' not Decoded')
                    pass
        
    IPv4frags_dict.clear()

def decodeIPv6(xdr,raw):
    # skip ttl, since ttl will be reduced alone with routers.
    raw_no_ttl = raw[:7] + raw[8:]
    #raw_no_ttl = raw
    found = status.ipv6_dup_list_1.get((xdr['Level'],raw_no_ttl),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup IPv6 Packet')
            return
    found = status.ipv6_dup_list_2.get((xdr['Level'],raw_no_ttl),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup IPv6 Packet')
            return
    found = status.ipv6_dup_list_3.get((xdr['Level'],raw_no_ttl),False)
    if found:
        if(xdr['ts'][0]*1000000000+xdr['ts'][1] - found[0]*1000000000-found[1] < status.MIN_DUP_DELAY):
            print(xdr['display'], 'Dup IPv6 Packet')
            return
    status.ipv6_dup_list_3 = status.ipv6_dup_list_2
    status.ipv6_dup_list_2 = status.ipv6_dup_list_1
    status.ipv6_dup_list_1 = {}
    status.ipv6_dup_list_1[(xdr['Level'],raw_no_ttl)] = xdr['ts']

    xdr['display'] += ', IPv6'
    xdr['Level'] += 1
    ver,tc,fl,payloadLength,nextHeader,Hop,sip,dip = struct.unpack('!2B2H2B16s16s',raw[:40])
    version = ver>>4
    trafficClass = (ver & 15)*16 + tc >>4
    flowLabel = (tc & 15) * 256*256 + fl
    
    if version != 6:                                       # it is a IPv6 packet
        print(xdr['display']+', IP version is not 6, it is ',version)

    xdr['IPv6'] = True
    xdr['sip'].append(sip)
    xdr['dip'].append(dip)
    
    pos = 40
    fragments = False

    length = len(raw)
    xdr['nextHeader'] = nextHeader
    while pos < length - 2:
        if nextHeader == 0:       # Next header: Hop-by-Hop Options (0)
            nextHeader,headerExtLength = struct.unpack('!2B',raw[pos:pos+2])
            pos += headerExtLength + 8
        elif nextHeader == 6:    # Next header: TCP (6)
            break
        elif nextHeader == 17:    # Next header: UDP (17)
            break
        elif nextHeader == 43:    # Next header: Routing (43)
            nextHeader,headerExtLength = struct.unpack('!2B',raw[pos:pos+2])
            pos += headerExtLength + 8
        elif nextHeader == 44:    # Next header: Fragment Header for IPv6 (44)
            nextHeader,res1,frag,iden = struct.unpack('!2BHI',raw[pos:pos+8])
            fragOffset = frag>>3
            more = frag & 1
            pos += 8
            if(fragOffset == 0 and more == 0):
                fragments = False
            else:
                fragments = True
                print(xdr['display'], ' Fragment')
            
            xdr['nextHeader'] = nextHeader

        elif nextHeader == 50:    # Next header: ESP (50)
            break
        elif nextHeader == 51:    # Next header: Authentication Header (51)
            break
        elif nextHeader == 60:    # Next header: Destination Options (60)
            nextHeader,headerExtLength = struct.unpack('!2B',raw[pos:pos+2])
            pos += headerExtLength + 8
        elif nextHeader == 135:   # Next header: Mobility (135)
            nextHeader,headerExtLength = struct.unpack('!2B',raw[pos:pos+2])
            pos += headerExtLength + 8
        else:
            break
    if fragments == True:
        if fragOffset !=0 or more != 0:
            level = xdr['Level']
            IPv6frags[level].append((xdr['sip'][-1],iden,fragOffset*8,payloadLength-pos+40,more,xdr,raw[pos:],xdr['nextHeader']))    # 0:sip(inner),1:iden,2:Offset,3:length,4:more,5:xdr,6:raw,7:nextHeader
            session_dict = {}
            for m in range(0,len(IPv6frags[level])):                       # check to see if we have collected all the fragments.
                n = IPv6frags[level][m]
                session_dict.setdefault((n[0],n[1]),[]).append(n)
            for m in session_dict:
                tail_exist = True if min([x[4] for x in session_dict[m]]) == 0 else False
                if tail_exist:
                    header_exist = True if min([x[2] for x in session_dict[m]]) == 0 else False
                    if header_exist:
                        is_recv_all = sum([x[3] for x in session_dict[m] if x[4] == 1]) == max([x[2] for x in session_dict[m]])
                        if is_recv_all:
                            sorted_list = sorted(session_dict[m], key = lambda x: x[2])
                            xdr = sorted_list[0][5]
                            raw = b"".join([x[6] for x in sorted_list])
                            nextHeader = xdr['nextHeader']
                            frags = []
                            RawData = []
                            RawData1 = []
                            for x in sorted_list:
                                frags = frags + x[5].get('frags',[x[5]['id']])
                                RawData = RawData + x[5]['RawData']
                                RawData1 = RawData1 + x[5]['RawData1']
                            xdr['frags'] = frags
                            xdr['RawData'] = RawData
                            xdr['RawData1'] = RawData1
                            pos = 0
                            payloadLength = len(raw)
                            for n in IPv6frags[level][::-1]:
                                if((n[0],n[1]) == m):
                                    IPv6frags[level].remove(n)
                        else:
                            return
                    else:
                        return
                else:
                    return
        else:
            return

    if nextHeader  == 1:
        #print(xdr['display'], ' ICMP not Decoded')
        pass
    elif nextHeader  == 6:
        if len(raw) == 32:
            print('tcp length is 0')
            del xdr
        else:
            tcp.decodeTCP(xdr,raw[pos:pos+payloadLength])
    elif nextHeader  == 17:
        #print(xdr['display'], ' UDP not Decoded')
        udp.decodeUDP(xdr,raw[pos:pos+payloadLength])
    elif nextHeader  == 50:                                  # ESP
        #print(xdr['display'], ' ESP not Decoded')
        esp.decodeESP(xdr,raw[pos:pos+payloadLength],False)
    elif nextHeader  == 58:                                  # ICMPv6
        print(xdr['display'], ' ICMPv6 not decoded')
    elif nextHeader  == 89:
        del xdr
        del raw
        pass
        #print(xdr['display'], ' OSPFIGP not Decoded')
    elif nextHeader  == 132:   
        if len(raw) <= 28:
            print('SCTP packet is too small')
            return
        sctp.decodeSCTP(xdr,raw[pos:])
    return

def flushIPv6():
    global IPv6frags
    for level in IPv6frags:
        for frag in level:
            protocol = frag[7]
            xdr = frag[5]
            raw = frag[6]
            if frag[2] == 0:
                if protocol  == 1:
                    print('Frame id:',frag[6]['id'],frag[6]['display'], ' ICMP not Decoded')
                    pass
                elif protocol  == 6:
                    print('Frame id:',xdr['id'], xdr['display'])
                    tcp.decodeTCP(xdr,raw)
                elif protocol  == 17:
                    print('Frame id:',xdr['id'],xdr['display'])
                    udp.decodeUDP(xdr,raw)
                elif protocol  == 50:
                    print('Frame id:',xdr['id'],xdr['display'])
                    esp.decodeESP(xdr,raw,True)
                elif protocol  == 89:
                    #print(xdr['display'], ' OSPFIGP not Decoded')
                    pass
                elif protocol  == 112:
                    #print(xdr['display'], ' (112) VRRP not Decoded')
                    pass
                elif protocol  == 114:
                    #print(xdr['display'], ' (114)any 0-hop protocol not Decoded')
                    pass
                elif protocol  == 132:
                    print('Frame id:',frag[6]['id'],xdr['display'])
                    sctp.decodeSCTP(frag[6],raw)
                    pass
                else:
                    print('Frame id:',frag[6]['id'],frag[6]['display'], protocol,' not Decoded')
                    pass
    IPv6frags = [[] for row in range(20)]

    
IPv4frags = [[] for row in range(20)]
IPv6frags = [[] for row in range(20)]

List = []