"""
Checks to see if resolvers send data in their SYN
Parses output pcap from `tfo_enabled_issuer.py` abd outputs a list of json objects
Used to identify which IPs had the TFO flag set when querying the authoritative server
"""


__author__ = "Jacob Davis as part of research at imaal.byu.edu"


import argparse
import subprocess
import shlex
import io
from tqdm import tqdm
import re
import socket
import base64
import json

src_ip = re.compile(r'IP6? (.+)?\.\d+ >')
tcp_flags = re.compile(r'Flags \[(.+?)\]')
tcp_options = re.compile(r'options \[(.+?)\]')
dns_query = re.compile(r'TXT\? (.+) ')
tfo_info = re.compile(r'tfo (.+?),')


def get(pattern, line):
    try:
        return pattern.search(line).group(1)
    except:
        return ""


# For reference, json output keys
O_IP = "original_ip"
S_IP = "src_ip"
TFO_S = "tfo_set"
TFO_I = "tfo_info"
SYN_D = "syn_data"
TCP_O = "tcp_opts"
ERR = "error"
json_keys = [O_IP, S_IP, TFO_S, TFO_I, SYN_D, TCP_O, ERR]


def get_og_ip(qname):
    def label_to_ip(label):
        """ Directly from qsnoop. Converts base32 labels back to IP address """
        if len(label) > 7:
            return socket.inet_ntop(socket.AF_INET6, base64.b32decode(label + '======'))
        else:
            return socket.inet_ntop(socket.AF_INET, base64.b32decode(label + '='))
    return label_to_ip(qname.split('.')[1].upper())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Running a series of scapy scans on a list of IPs to look for TFO")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="File to write results to. Default is stdout")
    parser.add_argument('keyword', help="Keyword that a qname must include. Used to filter out other packets")
    args = parser.parse_args()

    tcpdump = subprocess.Popen(shlex.split("tcpdump -nr {}".format(args.input)), stdout=subprocess.PIPE)
    non_data_syns = set()

    written_results = 0
    pbar = tqdm(io.TextIOWrapper(tcpdump.stdout, encoding="utf-8"))
    with open(args.output, 'w') as output_file:
        for line in pbar:
            # print(line)
            try:
                pbar.set_postfix_str('Written: {}'.format(written_results))
                flags = get(tcp_flags, line)
                # SYN
                if flags == "S":
                    s_ip = get(src_ip, line)
                    qname = get(dns_query, line)
                    if qname == "":
                        non_data_syns.add(s_ip)
                    elif args.keyword in qname and qname[0] == "2":
                        json_out = {key: None for key in json_keys}
                        json_out[O_IP] = get_og_ip(qname)
                        json_out[S_IP] = s_ip
                        json_out[TCP_O] = get(tcp_options, line)
                        json_out[TFO_S] = bool("tfo" in json_out[TCP_O])
                        json_out[TFO_I] = get(tfo_info, line)
                        json_out[SYN_D] = True
                        output_file.write(json.dumps(json_out) + '\n')
                        written_results += 1
                        if s_ip in non_data_syns:
                            non_data_syns.remove(s_ip)
            except Exception as e:
                print(e)
                print(line)
                e.with_traceback()

        for ip in non_data_syns:
            json_out = {key: None for key in json_keys}
            json_out[S_IP] = ip
            json_out[SYN_D] = False
            output_file.write(json.dumps(json_out) + '\n')

