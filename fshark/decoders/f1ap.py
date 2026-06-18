import datetime
import status
import struct
from socket import inet_ntop, AF_INET6, inet_ntoa

# dir双向时，给'0' 给'1'都可以，这里统一给'0'
# key是由TriggeringMessage-procedureCode拼接组成的
f1ap_dict = {
    '0-0': {'msgType': '50400', 'dir': '0'},
    '1-0': {'msgType': '50401', 'dir': '0'},
    '0-1': {'msgType': '50402', 'dir': '0'},
    '1-1': {'msgType': '50403', 'dir': '1'},
    '2-1': {'msgType': '50404', 'dir': '1'},
    '0-2': {'msgType': '50405', 'dir': '0'},
    '0-3': {'msgType': '50406', 'dir': '0'},
    '1-3': {'msgType': '50407', 'dir': '1'},
    '2-3': {'msgType': '50408', 'dir': '1'},
    '0-4': {'msgType': '50409', 'dir': '1'},
    '1-4': {'msgType': '50410', 'dir': '0'},
    '2-4': {'msgType': '50411', 'dir': '0'},
    '0-5': {'msgType': '50412', 'dir': '1'},
    '1-5': {'msgType': '50413', 'dir': '0'},
    '2-5': {'msgType': '50414', 'dir': '0'},
    '0-6': {'msgType': '50415', 'dir': '1'},
    '1-6': {'msgType': '50416', 'dir': '0'},
    '0-7': {'msgType': '50417', 'dir': '1'},
    '1-7': {'msgType': '50418', 'dir': '0'},
    '2-7': {'msgType': '50419', 'dir': '0'},
    '0-8': {'msgType': '50420', 'dir': '0'},
    '1-8': {'msgType': '50421', 'dir': '1'},
    '2-8': {'msgType': '50422', 'dir': '1'},
    '0-9': {'msgType': '50423', 'dir': '0'},
    '0-10': {'msgType': '50424', 'dir': '0'},
    '0-11': {'msgType': '50425', 'dir': '0'},
    '0-12': {'msgType': '50426', 'dir': '1'},
    '0-13': {'msgType': '50427', 'dir': '0'},
    '0-14': {'msgType': '50428', 'dir': '0'},
    '0-15': {'msgType': '50429', 'dir': '0'},
    '0-16': {'msgType': '50430', 'dir': '1'},
    '1-16': {'msgType': '50431', 'dir': '0'},
    '0-17': {'msgType': '50432', 'dir': '1'},
    '0-18': {'msgType': '50433', 'dir': '1'},
    '0-19': {'msgType': '50434', 'dir': '0'},
    '0-20': {'msgType': '50435', 'dir': '1'},
    '1-20': {'msgType': '50436', 'dir': '0'},
    '0-21': {'msgType': '50437', 'dir': '1'},
    '1-21': {'msgType': '50438', 'dir': '0'},
    '0-22': {'msgType': '50439', 'dir': '0'},
    '0-23': {'msgType': '50440', 'dir': '0'},
    '0-24': {'msgType': '50441', 'dir': '0'},
    '0-25': {'msgType': '50442', 'dir': '0'},
    '0-26': {'msgType': '50443', 'dir': '0'},
    '1-26': {'msgType': '50444', 'dir': '0'},
    '2-26': {'msgType': '50445', 'dir': '0'},
    '0-27': {'msgType': '50446', 'dir': '1'},
    '0-28': {'msgType': '50447', 'dir': '1'},
    '0-29': {'msgType': '50448', 'dir': '1'},
    '0-30': {'msgType': '50449', 'dir': '0'},
    '0-31': {'msgType': '50450', 'dir': '1'},
    '0-32': {'msgType': '50451', 'dir': '1'},
    '1-32': {'msgType': '50452', 'dir': '0'},
    '2-32': {'msgType': '50453', 'dir': '0'},
    '0-33': {'msgType': '50454', 'dir': '1'},
    '1-33': {'msgType': '50455', 'dir': '0'},
    '2-33': {'msgType': '50456', 'dir': '0'},
    '0-34': {'msgType': '50457', 'dir': '1'},
    '1-34': {'msgType': '50458', 'dir': '0'},
    '2-34': {'msgType': '50459', 'dir': '0'},
    '0-35': {'msgType': '50460', 'dir': '1'},
    '1-35': {'msgType': '50461', 'dir': '0'},
    '2-35': {'msgType': '50462', 'dir': '0'},
    '0-36': {'msgType': '50463', 'dir': '1'},
    '1-36': {'msgType': '50464', 'dir': '0'},
    '2-36': {'msgType': '50465', 'dir': '0'},
    '0-37': {'msgType': '50466', 'dir': '0'},
    '0-38': {'msgType': '50467', 'dir': '1'},
    '0-39': {'msgType': '50468', 'dir': '0'},
    '0-40': {'msgType': '50469', 'dir': '0'},
    '0-41': {'msgType': '50470', 'dir': '1'},
    '1-41': {'msgType': '50471', 'dir': '0'},
    '2-41': {'msgType': '50472', 'dir': '0'},
    '0-42': {'msgType': '50473', 'dir': '1'},
    '0-43': {'msgType': '50474', 'dir': '0'},
    '0-44': {'msgType': '50475', 'dir': '0'},
    '0-45': {'msgType': '50476', 'dir': '1'},
    '0-46': {'msgType': '50477', 'dir': '0'},
    '0-47': {'msgType': '50478', 'dir': '1'},
    '0-48': {'msgType': '50479', 'dir': '1'},
    '1-48': {'msgType': '50480', 'dir': '0'},
    '2-48': {'msgType': '50481', 'dir': '0'},
    '0-49': {'msgType': '50482', 'dir': '1'},
    '1-49': {'msgType': '50483', 'dir': '0'},
    '2-49': {'msgType': '50484', 'dir': '0'},
    '0-50': {'msgType': '50485', 'dir': '1'},
    '1-50': {'msgType': '50486', 'dir': '0'},
    '2-50': {'msgType': '50487', 'dir': '0'},
    '0-51': {'msgType': '50488', 'dir': '1'},
    '0-52': {'msgType': '50489', 'dir': '1'},
    '1-52': {'msgType': '50490', 'dir': '0'},
    '2-52': {'msgType': '50491', 'dir': '0'},
    '0-53': {'msgType': '50492', 'dir': '0'},
    '0-54': {'msgType': '50493', 'dir': '0'},
    '0-55': {'msgType': '50494', 'dir': '1'},
    '0-56': {'msgType': '50495', 'dir': '0'},
    '0-57': {'msgType': '50496', 'dir': '0'},
    '0-58': {'msgType': '50497', 'dir': '1'},
    '0-59': {'msgType': '50498', 'dir': '1'},
    '1-59': {'msgType': '50499', 'dir': '0'},
    '2-59': {'msgType': '50500', 'dir': '0'},
    '0-60': {'msgType': '50501', 'dir': '1'},
    '1-60': {'msgType': '50502', 'dir': '0'},
    '0-61': {'msgType': '50503', 'dir': '0'},
    '0-62': {'msgType': '50504', 'dir': '1'},
    '1-62': {'msgType': '50505', 'dir': '0'},
    '2-62': {'msgType': '50506', 'dir': '0'},
    '0-63': {'msgType': '50507', 'dir': '1'},
    '0-64': {'msgType': '50508', 'dir': '1'},
    '1-64': {'msgType': '50509', 'dir': '0'},
    '2-64': {'msgType': '50510', 'dir': '0'},
    '0-65': {'msgType': '50511', 'dir': '1'},
    '1-65': {'msgType': '50512', 'dir': '0'},
    '0-66': {'msgType': '50513', 'dir': '0'},
    '0-67': {'msgType': '50514', 'dir': '1'},
    '1-67': {'msgType': '50515', 'dir': '0'},
    '2-67': {'msgType': '50516', 'dir': '0'},
    '0-68': {'msgType': '50517', 'dir': '0'},
    '1-68': {'msgType': '50518', 'dir': '1'},
    '2-68': {'msgType': '50519', 'dir': '1'},
    '0-69': {'msgType': '50520', 'dir': '0'},
    '1-69': {'msgType': '50521', 'dir': '1'},
    '0-70': {'msgType': '50522', 'dir': '1'},
    '1-70': {'msgType': '50523', 'dir': '0'},
    '2-70': {'msgType': '50524', 'dir': '0'},
    '0-71': {'msgType': '50525', 'dir': '0'},
    '0-72': {'msgType': '50526', 'dir': '1'},
    '0-73': {'msgType': '50527', 'dir': '0'},
    '0-74': {'msgType': '50528', 'dir': '0'},
    '0-75': {'msgType': '50529', 'dir': '1'},
    '1-75': {'msgType': '50530', 'dir': '0'},
    '2-75': {'msgType': '50531', 'dir': '0'},
    '0-76': {'msgType': '50532', 'dir': '1'},
    '1-76': {'msgType': '50533', 'dir': '0'},
    '2-76': {'msgType': '50534', 'dir': '0'},
    '0-77': {'msgType': '50535', 'dir': '1'},
    '0-78': {'msgType': '50536', 'dir': '1'},
    '0-79': {'msgType': '50537', 'dir': '1'},
    '0-80': {'msgType': '50538', 'dir': '0'},
    '0-81': {'msgType': '50539', 'dir': '1'}
}


def decodeF1AP(xdr, raw):
    # 第一，第二个字节解码8位二进制
    first = format(struct.unpack('!B', raw[0:1])[0], '08b')
    second = format(struct.unpack('!B', raw[1:2])[0], '08b')
    # 获取key
    key = get_triggering_message(first) + '-' + get_procedure_code(second)
    xdr['msgType'] = f1ap_dict[key]['msgType']
    xdr['dir'] = f1ap_dict[key]['dir']
    xdr['keyword1'] = ''
    ts = "{}.{:0>9d}".format(datetime.datetime.fromtimestamp(xdr['ts'][0]).strftime('%Y-%m-%d %H:%M:%S'), xdr['ts'][1])
    if len(xdr['sip'][-1]) == 4:
        sip = inet_ntoa(xdr['sip'][-1])
    else:
        sip = inet_ntop(AF_INET6, xdr['sip'][-1])
    if len(xdr['dip'][-1]) == 4:
        dip = inet_ntoa(xdr['dip'][-1])
    else:
        dip = inet_ntop(AF_INET6, xdr['dip'][-1])
    status.file_mode_xdr.append('|'.join([xdr['id'], ts, '', '', sip, str(xdr['sport1']), dip, str(xdr['dport1']), '', 'F1', '', xdr['dir'], '', '', xdr['msgType'], '', '', '', '', '', '', '', xdr['keyword1'], '', '', '', '', "".join([x.hex() for x in xdr['RawData1']])[:status.MAX_LENGTH_OF_RAW]]))


def get_triggering_message(m):
    n = int(m[0:2], 2)
    return str(n)


def get_procedure_code(m):
    n = int(m, 2)
    return str(n)
