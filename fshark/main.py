#!/usr/bin/env python3
"""
fshark - CLI tool to decode pcap files into pipe-delimited XDR output.
Reads a single pcap file, auto-detects 4G/5G, outputs to a single file.
"""

import sys
import os
import argparse
import datetime
import re
import shutil
import tempfile

# Ensure fshark/ and fshark/decoders/ are on sys.path so bare imports resolve correctly
_fshark_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _fshark_dir)
sys.path.insert(0, os.path.join(_fshark_dir, 'decoders'))

import status
import pcap
import sip
import ip as ip_mod
import s1ap
import ngap
import diameter
import sgsap
import gtpv2
import epcDNS
import gtp
import gb
import m3ua
import pfcp
import http2
import ethernet
import linuxcooked
import lte_uu


def decodeFile(fileList, net_type):
    """Core decode loop -- reads pcap, dispatches packets, flushes buffers."""
    status.logFile.writelines('in file %s\n' % fileList)
    if pcap.pcapFiles(fileList) == -1:
        return
    timeval = 0
    id_list = [1] * len(fileList)
    while timeval != None:
        m, timeStamp, timeval, recordCapLen, recordLen, idid = pcap.nextPacket()
        if timeval == None:
            break
        xdr = {}
        xdr['id'] = '.'.join([str(m), str(idid)])
        xdr['Level'] = 0
        xdr['ts'] = timeval
        xdr['RawData'] = []
        xdr['RawData'].append(pcap.pcapRAW)
        xdr['RawData1'] = []
        xdr['RawData1'].append(pcap.pcapRAW)
        xdr['sip'] = []
        xdr['dip'] = []
        xdr['msisdn'] = ''
        linktype = pcap.pcapFileHandles[m]['linktype']
        try:
            if recordCapLen != recordLen:
                pass  # truncated packet, still attempt decode
            if linktype == 1:                  # WTAP_ENCAP_ETHERNET
                xdr['display'] = 'WTAP_ENCAP_ETHERNET'
                ethernet.decodeEthernet(xdr, pcap.pcapRAW[16:])
            elif linktype == 101:              # WTAP_ENCAP_RAW_IP
                xdr['display'] = 'WTAP_ENCAP_RAW_IP'
                xdr['RawData'] = [pcap.pcapRAW[16:]]
                if xdr['RawData'][0][0] // 16 == 4:
                    ip_mod.decodeIPv4(xdr, pcap.pcapRAW[16:])
                else:
                    ip_mod.decodeIPv6(xdr, pcap.pcapRAW[16:])
            elif linktype == 113:              # WTAP_ENCAP_SLL
                xdr['display'] = 'WTAP_ENCAP_SLL'
                linuxcooked.decodeLinuxcooked(xdr, pcap.pcapRAW[16:])
            elif linktype in [147, 148, 149, 150, 151, 152, 153, 154, 155]:
                if net_type == '4G':
                    xdr['display'] = 'WTAP_ENCAP_LTE_UU'
                    lte_uu.decode_lte_uu(xdr, linktype)
            else:
                if linktype not in [10, 107, 177, 235]:
                    print('Unknown linktype:', linktype)
            id_list[m] += 1
        except:
            pass

    # Flush all protocol buffers
    ip_mod.flushIPv4()
    ip_mod.flushIPv4()
    ip_mod.flushIPv6()
    ip_mod.flushIPv6()
    s1ap.flushNASXDR()
    s1ap.flushS1APXDR()
    s1ap.flushS1APNASCPlatency()
    diameter.flushTCP()
    diameter.flushCXXDR()
    diameter.flushGXXDR()
    diameter.flushRXXDR()
    diameter.flushS13XDR()
    diameter.flushS6AXDR()
    diameter.flushS9XDR()
    diameter.flushSHXDR()
    sgsap.flushSGSXDR()
    gtpv2.flushS11XDR()
    gtpv2.flushN26XDR()
    epcDNS.flushIMSEPCDNSXDR()
    epcDNS.flushLTEEPCDNSXDR()
    gtp.flushGNGPXDR()
    gb.flushGBXDR()
    gb.flushNASXDR()
    m3ua.flushRANAPXDR()
    m3ua.flushBICCXDR()
    ngap.flushNASXDR()
    ngap.flushngapXDR()
    ngap.flushngapnasCPLatency()
    pfcp.flushPFCPXDR()
    http2.flush_http2_response_cache()

    # Rename .tmp -> .dat for all output files
    for file in status.outputFileList:
        tmpFileName = file.name
        datFileName = re.sub('tmp', 'dat', tmpFileName)
        file.flush()
        file.close()
        if os.path.isfile(datFileName): os.remove(datFileName)
        os.renames(tmpFileName, datFileName)
    return


def load_seq_ipcfg(ipcfg_path):
    """Load seq.ipcfg to populate SIP network element IP lists."""
    if not os.path.exists(ipcfg_path):
        return
    with open(ipcfg_path, 'r') as ipcfg:
        for line in ipcfg:
            for pattern in [r'AS[^=]*=(.*)', r'SCSCF[^=]*=(.*)',
                            r'MGCF[^=]*=(.*)', r'SBC[^=]*=(.*)',
                            r'BGCF[^=]*=(.*)', r'ICSCF[^=]*=(.*)']:
                m = re.match(pattern, line)
                if m:
                    sip.loadIPcfg(line)
                    break


def main():
    parser = argparse.ArgumentParser(
        description='fshark - Decode pcap file to pipe-delimited XDR output',
        prog='fshark'
    )
    parser.add_argument('-f', '--file', default=None,
                        help='Input pcap/pcapng file path')
    parser.add_argument('-o', '--output', default=None,
                        help='Output XDR file path')
    parser.add_argument('-G', '--config', default=None,
                        help='Path to LteConfig.ini (default: <fshark_dir>/cfg/LteConfig.ini)')
    parser.add_argument('-I', '--ipcfg', default=None,
                        help='Path to seq.ipcfg (default: <fshark_dir>/cfg/seq.ipcfg)')
    parser.add_argument('-v', '--version', action='store_true',
                        help='Print version and exit')
    args = parser.parse_args()

    if args.version:
        print(status.VERSION)
        print(status.COMMENT)
        sys.exit(0)

    # Validate required args for decode mode
    if not args.file or not args.output:
        parser.error('the following arguments are required: -f/--file, -o/--output')

    # Validate input file
    pcap_file = os.path.abspath(args.file)
    if not os.path.isfile(pcap_file):
        print("Error: Input file not found: %s" % pcap_file, file=sys.stderr)
        sys.exit(1)

    output_file = os.path.abspath(args.output)

    # Determine fshark directory (where this script lives)
    fshark_dir = os.path.dirname(os.path.abspath(__file__))
    cfg_dir = os.path.join(fshark_dir, 'cfg')

    # Create temp working directory
    base_dir = tempfile.mkdtemp(prefix='fshark_')
    try:
        # Set up log directory
        log_dir = os.path.join(base_dir, 'log')
        os.makedirs(log_dir)
        log_file_name = os.path.join(log_dir, 'fshark.log')
        status.logFile = open(log_file_name, 'w')

        # Set up SDL (temp output) directory
        sdl_dir = os.path.join(base_dir, 'sdl')
        os.makedirs(sdl_dir)
        status.sdlDirectory = sdl_dir

        # Set up filter directory (not used but expected by some modules)
        filter_dir = os.path.join(base_dir, 'filter')
        os.makedirs(filter_dir)
        status.filterDirectory = filter_dir

        # Load config ini
        config_path = args.config or os.path.join(cfg_dir, 'LteConfig.ini')
        if os.path.isfile(config_path):
            status.configiniFile = open(config_path, 'r')
        else:
            print("Warning: Config file not found: %s" % config_path, file=sys.stderr)
            status.configiniFile = open(os.devnull, 'r')

        # No license check
        status.licenseFile = None

        # Load seq.ipcfg for SIP network element IPs
        ipcfg_path = args.ipcfg or os.path.join(cfg_dir, 'seq.ipcfg')
        load_seq_ipcfg(ipcfg_path)

        # Auto-detect net_type: default '4G'
        # S1AP/NGAP are auto-detected at SCTP layer regardless of this setting.
        # net_type only affects linktype 147-155 (LTE-UU radio capture).
        net_type = '4G'

        # Clear any existing SDL files
        for root, dirs, files in os.walk(sdl_dir):
            for filename in files:
                os.remove(os.path.join(root, filename))

        # Run decode (output_sip_xdr is called inside sipCorrelation)
        decodeFile([pcap_file], net_type)
        sip.sipCorrelation()

        # Post-process: merge file_mode_xdr and file_mode_CPlatency
        xdr_list = []
        for line in status.file_mode_xdr:
            f = line.strip().split("|")
            xdr_list.append(f)

        cplatency_list = []
        for line in status.file_mode_CPlatency:
            f = line.strip().split("|")
            if len(f[10]) < 10:
                cplatency_list.append(f[:7] + [''] + f[7:12] + [''] + f[12:])
            else:
                cplatency_list.append(f)

        xdr_list = sorted(xdr_list, key=lambda x: x[1])
        cplatency_list = sorted(cplatency_list, key=lambda x: x[10])

        cursor = 0
        len_cplatency_list = len(cplatency_list)
        result_xdr_list = []
        for line_no, xdr in enumerate(xdr_list, 0):
            while cursor < len_cplatency_list and xdr[1][:-3] >= cplatency_list[cursor][10]:
                if xdr[0][:-3] == cplatency_list[cursor][10]:
                    procType = status.file_mode_CPlatency_dict.get(xdr[12], None)
                    if procType == cplatency_list[cursor][12]:
                        xdr[10] = cplatency_list[cursor][17]  # Cause
                        xdr[11] = cplatency_list[cursor][11]  # succFlag
                        xdr[13] = cplatency_list[cursor][14]  # latency
                        xdr[14] = cplatency_list[cursor][16]  # retrs
                cursor += 1
            result_xdr_list.append(xdr[1:])

        # Write single output file
        output_count = 0
        with open(output_file, 'w', encoding='utf-8') as out:
            for i, f in enumerate(result_xdr_list):
                if i >= 30000:
                    break
                f[-6] = f[-6][:status.MAX_LENGTH_OF_KEYWORD1]
                out.write("|".join(f) + "\n")
                output_count += 1

        print("Decoded %d XDR records to %s" % (output_count, output_file))

    finally:
        # Cleanup
        if status.logFile:
            status.logFile.flush()
            status.logFile.close()
        if status.configiniFile:
            status.configiniFile.close()
        # Remove temp directory
        shutil.rmtree(base_dir, ignore_errors=True)


if __name__ == '__main__':
    main()
