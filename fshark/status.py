import sys
import os
import struct
import base64
import datetime
import binascii
import pcap
from collections import Counter

#global
VERSION = 'v1.0.3'      # bug fix, ip frag, tcp frag, http2 frag
VERSION = 'v1.0.4'      # bug fix, MEGACO/H.248
VERSION = 'v1.0.5'      # bug fix, change opc/dpc format from integer to 3-8-3 ITU format
VERSION = 'v1.0.6'      # bug fix, UDP/DNS packet too short.
VERSION = 'v1.0.7'      # bug fix, http2/json. \xaa\xaa issue, introduced by Data Masking Process.
VERSION = 'v1.0.8'      # bug fix, wrong direction of N26 message.
VERSION = 'v1.0.9'      # bug fix, before SIP Route header compare operation, did not check the number of Route header.
VERSION = 'v1.0.10'     # Add Function, add HTTP/1.1 SBI interface support.
VERSION = 'v1.0.11'     # bug fix, SCTP DATA packet parsing error.
VERSION = 'v1.0.12'     # bug fix, UDP Fragment, pfcp decode, add length guard for frag.
VERSION = 'v1.0.13'     # bug fix, ipv4 frag, GTP, ipv6 frag. test case #0011
VERSION = 'v1.0.14'     # Add Function, leave only one ngap paging msg,delete the others. Not tested, because there is no pcap with ngap paging.
VERSION = 'v1.0.15'     # bug fix, paging (S1AP)
VERSION = 'v1.1.0'      # Add function, check_dup.py merged into test.py and change chk file format, delete line_no
VERSION = 'v1.1.1'      # bug fix, for missing fragments, decode one by one
VERSION = 'v1.1.2'      # bug fix, ngap malformat, http2 malformat, Gm error.
VERSION = 'v1.1.3'      # Add function, add LIR as an indicator for I-CSCF.
VERSION = 'v1.1.4'      # bug fix, IP frag, RAW IP, test_case_00013.
VERSION = 'v1.1.5'      # bug fix, caplen != len
VERSION = 'v1.1.6'      # Add function, add EBI 和 PEM
VERSION = 'v1.1.7'      # bug fix, PEM with Regex.Matches(tmp, "(?:P-Early-Media:\s)(?:sendrecv|sendonly|recvonly|inactive)")
                        # bug fix, 4G with 888884000000000 IMSI, 5G with 888885000000000 IMSI
                        # bug fix, SIP latency
                        # Delete function, delete call-id in SIP keyword1.
                        # Add function, 4G ESR, cs fallback
                        # Add function, Cx(I-CSCF, S-CSCF), Sh(AS), add to keyword4
VERSION = 'v1.1.8'      # bug fix, 2_vlan_tags, avp_length_is_zero, sip_dissensitive with zero filled auth resx info in diameter, ngap "PDU SESSION RESOURCE RELEASE COMMAND" direction is wrong.
VERSION = 'v1.1.9'      # bug fix, linux_cooked_capture pcap file cannot decode by pcap2txt and pcap2hex
VERSION = 'v1.1.10'     # bug fix, s1ap imsi extract error
VERSION = 'v1.1.11'     # Add funcation, SDP Video, change the order of MF, PEM, CSeq, SDP.Audio
VERSION = 'v1.1.12'     # Bug fix, SIP Register has not keyword1, which causes the failure at sequence_diagrams().
                        # Add Function, Add PEM and SDP.info to SIP respnonse message.
VERSION = 'v1.1.13'     # Bug fix, change msgType(50234) from N8 to N11, dir = 1. sbi_dict.py
                        # Buf fix, change content Request(31002) msg direction from 1 to 0
VERSION = 'v1.1.14'
COMMENT = '''Bug fix, SIP bug
Buf fix, S1AP bug'''

VERSION = 'v1.1.15'
COMMENT = '''Bug fix, decoder fails to fill keyword1, because of REGISTER in REGISTER'''

VERSION = 'v1.1.16'
COMMENT = '''Bug fix, for ciphered NAS msg, delete xdr'''

VERSION = 'v1.1.17'
COMMENT = '''Bug fix, N26 Context Request direction
Bug fix, N8 Deregistration Notification'''

VERSION = 'v1.1.18'
COMMENT = '''Bug fix, SIP MESSAGE direction.'''

VERSION = 'v1.1.19'
COMMENT = '''Bug fix, N26 Context Acknowledge direction.
Bug fix, pcap can not be opened, because imcomplete SIP and http2 message.
Bug fix, N7 bug.
Bug fix, SCSCF in Routes header.
'''

VERSION = 'v1.1.20'
COMMENT = '''
Add Function: MAX_LENGTH_OF_KEYWORD1 sets to 198
'''

VERSION = 'v1.1.21'
COMMENT = '''
Bug Fix: I2 dir dir is wrong.
Bug Fix: http2_DATA_fragments.
'''

VERSION = 'v1.1.22'
COMMENT = '''
Bug Fix: Force IPv6 to be Gm interface.
'''

VERSION = 'v1.1.23'
COMMENT = '''
Bug Fix: icscf/ibcf check.
Bug Fix: 408_07.cm.pcap\408_11.pcap flow chart not show
Bug Fix: packet duplicate removal
'''
VERSION = 'v1.1.24'     # 根据route指向atcf来判断本端是emsc不够准确，仅作为没有其他依据时的候选值；正则匹配前将*替换成#，避免产生歧义；
VERSION = 'v1.1.25'     # check VXLAN
VERSION = 'v1.1.26'     # 新增Ici接口，IBCF -> IBCF [ibcf.pcap]
VERSION = 'v1.1.27'     # MEGACO/H.248 xdr['strValue']调整 [megaco-h248.pcap]
VERSION = 'v1.1.28'     # GmOverGTP区分4G(eNB->PGW)，5G(gNB->UPF) 5GGmOverGTP [5g-gmovergtp.pcap]
VERSION = 'v1.1.29'     # 注释invite消息中判断Mw4接口的代码，ISC接口识别逻辑更新
VERSION = 'v1.1.30'     # 新增find_duplicate_ip函数，用于判断同一个ip是否被重复添加到多个网元列表中
VERSION = 'v1.1.31'     # 输出port实现ip+port配置网元
VERSION = 'v1.1.32'     # Mw3 ISC纠正
VERSION = 'v1.1.33'     # 4g无线类型pcap解析 linktype 147-155 [radio_RRC_DL_CCCH.pcap]
VERSION = 'v1.1.34'     # 修复1207,1208流程图解析失败 [p1207.pcap,p1208.pcap]
VERSION = 'v1.1.35'     # 输出点码
VERSION = 'v1.1.36'     # 增加Ici接口的学习，更新sip_dict
VERSION = 'v1.1.37'     # m3ua.py 新增ISUP解析 [m3ua.pcap]
VERSION = 'v1.1.38'     # linuxcooked.py增加33024分支 [linuxcooked33024.pcap]
VERSION = 'v1.1.39'     # decode.py增加netType参数用于区分4G/5G软采
VERSION = 'v1.1.40'     # http2.py使用n2SmInfoType的值作为消息名称 [n2SmInfoType.pcap]
VERSION = 'v1.1.41'     # Ici接口网元错误问题修复
VERSION = 'v1.1.42'     # ip.py flushIPv4 避免报错：dictionary changed size during iteration [gtpu-sip.pcap]
VERSION = 'v1.1.43'     # RTP AMR解析（已搁置）[amr.pcap]
VERSION = 'v1.1.44'     # f1ap解析 [f1ap.pcap]
VERSION = 'v1.1.45'     # http2.py逻辑补充，输出没有请求消息，只有响应消息且响应码为409的xdr [1446.pcap]
VERSION = 'v1.1.46'     # sip.py Ici接口识别逻辑补充 [1493.pcap]
VERSION = 'v1.1.47'     # ngap.py 脱敏导致的ranueid异常，超出正常范围 [1686未脱敏.pcap]
VERSION = 'v1.1.48'     # 最多输出10000条数据 [_28_29Aug24Marietta.pcap]
                        # lte_uu.py 4G X2 Handover Cancel 解析 [_X2HO_Cancel_Aug3024Marietta.pcap]
                        # diameter.py S13 ME-Identity-Check 解析 [_M3_20240706_0642_0700_e_combined.pcap]
VERSION = 'v1.1.49'     # sip.py 增加AG接口，agcf -> scscf
VERSION = 'v1.1.50'     # gtpv2.py MSC_ip MME_ip [_1673_打不开_busy.pcap] [_1711_打不开_18863096509-15点35掉话.pcap] [_1730_无法打开X13465436267.pcap]
VERSION = 'v1.1.51'     # 最多输出30000条数据 [1789-17598条数据.pcap]
# VERSION = 'v1.1.33'     # 新增Mw5接口
# VERSION = 'v1.1.34'     # Mw2接口判断逻辑调整

# merge Paging msg(A, S1AP, NgAP)

MAX_LENGTH_OF_RAW = 999990
MIN_DUP_DELAY = 200000000

# length of keyword1
MAX_LENGTH_OF_KEYWORD1 = 198

# S1AP
enbueidDict = {}

# SGs
sgsLUDict = {}

# Diameter
cxSessionDict = {}
gxSessionDict = {}
rxSessionDict = {}
s13SessionDict = {}
s6aSessionDict = {}
s9SessionDict = {}
shSessionDict = {}

# Common
imsiStatus = {}
msisdnIMSI = {}
imsiMSISDN = {}


# File handle
logFile=None
sdlDirectory=None
filterDirectory=None
configFile=None
licenseFile=None
autoIPcfgFile=None

# Correlation between interfaces
randIMSI = {}
teidIMSI = {}

# eSRVCC
stnSRIMSI = {}

# Global output file list
outputFileList = []

callFlow = []

# The STN_SR lists are used to identify eMSC --> SBC call.
# There are total three list, each with one digit less, in order for a fuss match.
stn_sr_1 = {}
stn_sr_2 = {}
stn_sr_3 = {}

# http2 stream buffer
http2_buffer = {}

# ipv4/ipv6 dup delete
ipv4_dup_ts = 0
ipv4_dup_list_1 = {}
ipv4_dup_list_2 = {}
ipv4_dup_list_3 = {}
ipv6_dup_ts = 0
ipv6_dup_list_1 = {}
ipv6_dup_list_2 = {}
ipv6_dup_list_3 = {}

# ipv4/ipv6 dup delete
udp_dup_ts = 0
udp_dup_list_1 = {}
udp_dup_list_2 = {}
udp_dup_list_3 = {}
tcp_dup_ts = 0
tcp_dup_list_1 = {}
tcp_dup_list_2 = {}
tcp_dup_list_3 = {}

# file_mode
file_mode_xdr = []
file_mode_CPlatency = []
file_mode_CPlatency_dict = {"1053":"3500", "1055":"3800", "1037":"2602", "1035":"2601", "1007":"2703", "388":"1407", "358":"1401", "1009":"2704", "1011":"2705", "1015":"3100", "1017":"3600", "1019":"3700", "1021":"3400", "1023":"3200", "1039":"2603", "1041":"2600", "1043":"2901", "1045":"2902", "1046":"2900", "1033":"2503", "1049":"2800", "605":"2400", "1051":"3300", "501":"1700", "505":"1701", "509":"1702", "601":"1800", "350":"1405", "231":"1006", "249":"1010", "288":"1102", "176":"2", "177":"6", "386":"1004", "202":"1013", "154":"24", "155":"27", "116":"8", "158":"13", "161":"4", "166":"11", "167":"12", "171":"10", "122":"9", "113":"18", "125":"19", "106":"15", "340":"1311", "342":"1310", "510":"1900", "281":"1113", "287":"1020", "291":"1108", "299":"1110", "104":"20", "132":"7", "124":"3", "128":"29", "131":"21", "136":"23", "142":"22", "145":"26", "149":"25", "317":"1303", "319":"1309", "322":"1202", "324":"1201", "326":"1204", "328":"1203", "330":"1207", "332":"1205", "334":"1206", "336":"1200", "345":"1406", "348":"1404", "353":"1403", "357":"1400", "164":"5", "109":"14", "120":"1", "337":"1312", "1001":"2701", "1003":"2702", "1005":"2700", "1025":"3000", "1027":"2500", "1029":"2502", "1031":"2501", "173":"28", "309":"1308", "311":"1306", "313":"1304", "315":"1307", "212":"1002", "215":"1014", "217":"1015", "220":"1016", "222":"1003", "228":"1009", "229":"1005", "235":"1017", "238":"1018", "240":"1019", "241":"1007", "245":"1008", "246":"1011", "253":"1112", "257":"1105", "259":"1106", "262":"1104", "265":"1103", "369":"1402", "371":"1600", "373":"1602", "376":"1603", "378":"1601", "205":"1012", "206":"1001", "209":"1000", "303":"1302", "305":"1301", "307":"1300", "426":"1504", "503":"1703", "507":"1704", "603":"1801", "512":"1901", "900":"999", "803":"5802", "805":"5801", "807":"5800", "809":"5808", "811":"5806", "813":"5804", "815":"5807", "817":"5803", "819":"5809", "840":"5811", "842":"5810", "391":"2300", "392":"2301", "393":"2302", "271":"1101", "273":"1100", "275":"1107", "399":"1313", "950":"998", "573":"1314", "575":"1315", "582":"1316", "585":"1317", "587":"1318", "595":"1319", "597":"1320", "30300":"6010", "30302":"6011", "30304":"6012", "30306":"6013", "30308":"6014", "30311":"6015", "30313":"6016", "30315":"6017", "30317":"6018", "30319":"6019", "30321":"6020", "50000":"6500", "50002":"6501", "50004":"6502", "50006":"6503", "50008":"6504", "50010":"6505", "50012":"6506", "50014":"6507", "50016":"6508", "50018":"6509", "50020":"6510", "50022":"6511", "50026":"6513", "50028":"6514", "50030":"6515", "50032":"6516", "50034":"6517", "50036":"6518", "50038":"6519", "50040":"6520", "50042":"6521", "50044":"6522", "50046":"6523", "50048":"6524", "50050":"6525", "50052":"6526", "50054":"6527", "50056":"6528", "50058":"6529", "50060":"6530", "50062":"6531", "50064":"6532", "50066":"6533", "50068":"6534", "50070":"6535", "50072":"6536", "50074":"6537", "50078":"6539", "50080":"6540", "50082":"6541", "50084":"6542", "50086":"6543", "50088":"6544", "50090":"6545", "50092":"6546", "50094":"6547", "50096":"6548", "50098":"6549", "50100":"6550", "50102":"6551", "50104":"6552", "50106":"6553", "50108":"6554", "50110":"6555", "50112":"6556", "50114":"6557", "50116":"6558", "50120":"6560", "50122":"6561", "50124":"6562", "50126":"6563", "50128":"6564", "50130":"6565", "50134":"6567", "50136":"6568", "50138":"6569", "50140":"6570", "50142":"6571", "50146":"6573", "50148":"6574", "50150":"6575", "50156":"6578", "50158":"6579", "50160":"6580", "50164":"6582", "50166":"6583", "50168":"6584", "50170":"6585", "50172":"6586", "50174":"6587", "50176":"6588", "50178":"6589", "50180":"6590", "50182":"6591", "50186":"6593", "50188":"6594", "50190":"6595", "50192":"6596", "50194":"6597", "50196":"6598", "50200":"6600", "50202":"6601", "50204":"6602", "50206":"6603", "50208":"6604", "50210":"6605", "50212":"6606", "50214":"6607", "50216":"6608", "50218":"6609", "50222":"6611", "50224":"6612", "50226":"6613", "50228":"6614", "50230":"6615", "50232":"6616", "50234":"6617", "50236":"6618", "50238":"6619", "50240":"6620", "50242":"6621", "50244":"6622", "50246":"6623", "50248":"6624", "50250":"6625", "50252":"6626", "50254":"6627", "50256":"6628", "50258":"6629", "50260":"6630", "50262":"6631", "50266":"6633", "50268":"6634", "50270":"6635", "50272":"6636", "50274":"6637", "50278":"6639", "50280":"6640", "50282":"6641", "50286":"6643", "50288":"6644", "50292":"6646", "50294":"6647", "50296":"6648", "50298":"6649", "50300":"6650", "50302":"6651", "50306":"6653", "50308":"6654", "50310":"6655", "50312":"6656", "50314":"6657", "50316":"6658", "50318":"6659", "50322":"6661", "50326":"6663", "50328":"6664", "50330":"6665", "50334":"6667", "50336":"6668", "50338":"6669", "50340":"6670", "50342":"6671", "50346":"6673", "50348":"6674", "50350":"6675", "50352":"6676", "50500":"6750", "1015":"3100", "1017":"3101", "1019":"3102", "1021":"3103", "1023":"3104", "1025":"3105", "1051":"3106", "1053":"3107", "1055":"3108", "1057":"3109", "1059":"3110", "1061":"3111", "1063":"3112", "1065":"3113", "1067":"3114", "1069":"3115", "1071":"3115", }
# SIP
sipXDR = []
sipStatus = {}
sipLatency = []