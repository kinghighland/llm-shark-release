import datetime
import struct
import status

link_type_dict = {
    147: {'interface': 'X2', 'type': 'x2ap'},  # eNB->eNB
    148: {'interface': 'Uu', 'type': 'lte-rrc.bcch.bch'},  # ue->eNB
    149: {'interface': 'Uu', 'type': 'lte-rrc.bcch.dl.sch'},
    150: {'interface': 'Uu', 'type': 'lte-rrc.mcch'},
    151: {'interface': 'Uu', 'type': 'lte-rrc.pcch'},
    152: {'interface': 'Uu', 'type': 'lte-rrc.dl.ccch'},
    153: {'interface': 'Uu', 'type': 'lte-rrc.dl.dcch'},
    154: {'interface': 'Uu', 'type': 'lte-rrc.ul.ccch'},
    155: {'interface': 'Uu', 'type': 'lte-rrc.ul.dcch'}
}
# x2ap
x2ap_message_type_dict = {
    0: {0: '12058', 1: '12059', 2: '12077'},
    1: {0: '12057'},
    2: {0: '22006'},
    3: {0: '12078'},
    4: {0: '12060'},
    5: {0: '12061'},
    6: {0: '12050', 1: '12051', 2: '12056'},
    7: {0: '12048', 1: '12049'},
    8: {0: '12053', 1: '12054', 2: '12055'},
    9: {0: '22016', 1: '22017', 2: '22018'},
    10: {0: '22019'},
    11: {0: '12079'},
    12: {0: '22020', 1: '22021', 2: '22022'},
    13: {0: '12069'},
    14: {0: '12070'},
    15: {0: '22025', 1: '22026', 2: '22027'},
    16: {0: '28198'},
    17: {0: '28199'},
    18: {0: '12080', 1: '12081', 2: '12082'},
    19: {0: '12083', 1: '12084', 2: '12085'},
    20: {0: '12086'},
    21: {0: '12087', 1: '12088', 2: '12089'},
    22: {0: '12090', 1: '12091', 2: '12092'},
    23: {0: '12093'},
    24: {0: '12094', 1: '12095'},
    25: {0: '12096'},
    26: {0: '12097', 1: '12098', 2: '12099'},
    27: {0: '12100', 1: '12101', 2: '12102'},
    28: {0: '12103'},
    29: {0: '12104', 1: '12105', 2: '12106'},
    30: {0: '12107', 1: '12108', 2: '12109'},
    31: {0: '12110', 1: '12111', 2: '12112'},
    32: {0: '12113', 1: '12114'},
    33: {0: '12115'},
    34: {0: '12116', 1: '12117', 2: '12118'},
    35: {0: '12119'},
    36: {0: '12120', 1: '12121', 2: '12122'},
    37: {0: '12123', 1: '12124', 2: '12125'},
    38: {0: '12126'},
    39: {0: '12127', 1: '12128', 2: '12129'},
    40: {0: '12130', 1: '12131'},
    41: {0: '12132', 1: '12133'},
    42: {0: '12134'},
    43: {0: '12135', 1: '12136', 2: '12137'},
    44: {0: '12138'},
    45: {0: '12139'},
    46: {0: '12140'},
    47: {0: '12141'},
    48: {0: '12142'},
    49: {0: '12143'},
    50: {0: '12144'},
    51: {0: '12145'},
    52: {0: '12146'},
    53: {0: '12147'},
    54: {0: '12148', 1: '12149', 2: '12150'},
    55: {0: '12151'},
    56: {0: '12152', 1: '12153'}
}
# 类似10029这些值是数据库中定义的msgType，需要映射关联起来，用于显示消息名，列表是有序的，与规范里的choice对应，多维列表表示规范里有多个choice
bcch_bch_message_list = ['10068']
bcch_dl_sch_message_list = [['10022', '10023']]
mcch_message_list = [['10066'], ['10067']]
pcch_message_list = ['10065']
dl_ccch_message_list = [['10024', '10004', '10013', '10001'], ['10064']]
dl_dcch_message_list = ['10057', '10006', '10058', '10007', '10008', '10005', '10009', '10010', '10059', '10027', '10060', '10061', '10062', '10063']
ul_ccch_message_list = [['10003', '10002'], ['10055'], ['10056']]
ul_dcch_message_type_list = [
    ['10029', '10011', '10013', '10025', '10012', '10017', '10018', '10019', '10032', '10016', '10025', '10026', '10036', '10037', '10038', '10034'],
    ['10039', '10040', '10041', '10042', '10043', '10044', '10045', '10046', '10047', '10048', '10049', '10050', '10051', '10052', '10053', '10054']
]


def decode_lte_uu(xdr, linktype):
    xdr['interface'] = link_type_dict[linktype]['interface']
    xdr['msgType'] = get_message_type(xdr['RawData1'][0], linktype)
    xdr['dir'] = get_dir(linktype, xdr['msgType'])
    xdr['keyword2'] = link_type_dict[linktype]['type']
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'), xdr['ts'][1])
    sip, dip = get_sip_dip(linktype)
    # 过滤掉没有msgType的消息
    if xdr['msgType'] != '':
        status.file_mode_xdr.append('|'.join([xdr['id'], ts, '', '', sip, '8080', dip, '8080', '', xdr['interface'], '', xdr['dir'], '', '', xdr['msgType'],
                                              '', '', '', '', '', '', '', '', xdr['keyword2'], '', '', '', "".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))


def get_message_type(raw, linktype):
    # rrc层第一个字节解析成8位二进制数
    rrc1 = format(struct.unpack('!B', raw[16:17])[0], '08b')
    if linktype == 147:
        return get_x2ap_message_type(raw, rrc1)
    elif linktype == 148:
        return get_bcch_bch_message_type(rrc1)
    elif linktype == 149:
        return get_bcch_dl_sch_message_type(rrc1)
    elif linktype == 150:
        return get_mcch_message_type(rrc1)
    elif linktype == 151:
        return get_pcch_message_type(rrc1)
    elif linktype == 152:
        return get_dl_ccch_message_type(rrc1)
    elif linktype == 153:
        return get_dl_dcch_message_type(rrc1)
    elif linktype == 154:
        return get_ul_ccch_message_type(rrc1)
    elif linktype == 155:
        return get_ul_dcch_message_type(rrc1)


def get_x2ap_message_type(raw, m):
    if (m[0] == '0'):
        s = int(m[1:3], 2)  # 解status
        p = struct.unpack('!B', raw[17:18])[0]  # 解 procedure
        return x2ap_message_type_dict[p][s]
    else:
        print('Not processed m[0] = 1 yet!')
        return ''


def get_bcch_bch_message_type(m):
    return bcch_bch_message_list[0]


def get_bcch_dl_sch_message_type(m):
    i = int(m[0])
    j = int(m[1])
    if i == 0:
        return bcch_dl_sch_message_list[i][j]
    return ''


def get_mcch_message_type(m):
    i = int(m[0])
    return mcch_message_list[i][0]


def get_pcch_message_type(m):
    i = int(m[0])
    if i == 0:
        return pcch_message_list[0]
    return ''


def get_dl_ccch_message_type(m):
    i = int(m[0])
    j = int(m[1:3], 2)
    return dl_ccch_message_list[i][j]


def get_dl_dcch_message_type(m):
    i = int(m[0])
    j = int(m[1:5], 2)
    return dl_dcch_message_list[j]


def get_ul_ccch_message_type(m):
    i = int(m[0])
    j = int(m[1])
    if i == 0:
        return ul_ccch_message_list[i][j]
    else:
        return ul_ccch_message_list[i+j][0]


def get_ul_dcch_message_type(m):
    i = int(m[0])
    j = int(m[1:5], 2)
    return ul_dcch_message_type_list[i][j]


def get_dir(linktype, msgType):
    if linktype == 147 and msgType in ['12059', '12061', '12077'] or linktype in [148, 149, 150, 151, 152, 153]:
        return '1'
    return '0'


def get_sip_dip(linktype):
    ip1 = '::ffff'
    ip2 = '10.10.95.27'
    ip3 = '10.10.80.80'
    if linktype == 147:
        return ip2, ip3
    elif linktype in [148, 149, 150, 151, 152, 153]:
        return ip2, ip1
    return ip1, ip2
