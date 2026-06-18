import sys
import os
import struct
import base64
import datetime
from collections import Counter
import pcap

def decodeICMP(start,end):
    return struct.unpack('!2B',pcap.pcapRAW[start:start+2])
