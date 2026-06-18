import os, sys
import re

def check_ip(ip_addr):
    m = re.match('^\d+(\.\d+){3}$', ip_addr)
    if m:
        return "IPv4"
    m = re.match('^[0-9a-fA-F]+(\:[0-9a-fA-F]*){4}', ip_addr)
    if m:
        return "IPv6"
    return None

if __name__ == "__main__":
    interface_dict = {}
    for root, dirs ,files in os.walk("result1"):
        for file_name in files:
            full_name = os.path.join(root, file_name)
            if(full_name[-4:] == '.txt' and full_name[-8:] != '.log.txt' ):
                with open(full_name) as fp:
                    for line_no, line in enumerate(fp, 1):
                        f = line.strip().split('|')
                        result = check_ip(f[4])
                        if(result == 'IPv6' and f[7] == 'SIP'):
                            # print(f[7])
                            interface_dict[f[7]] = 1
                            print(file_name)
