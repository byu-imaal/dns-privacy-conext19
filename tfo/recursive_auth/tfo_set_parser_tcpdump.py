"""
Parses output pcap from `tfo_set_issuer.py` abd outputs a list of json objects
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
json_keys = ["original_ip", "src_ip", "tfo_set", "tfo_info", "tcp_opts"]


def get_og_ip(qname):
    def label_to_ip(label):
        """ Converts base32 labels back to IP address """
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
    syn_packets = {}

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
                    opts = get(tcp_options, line)
                    # NO DATA
                    if qname == "":
                        syn_packets[s_ip] = opts
                    elif args.keyword in qname:  # HAS DATA so record now and move on
                        json_out = {key: None for key in json_keys}
                        json_out["original_ip"] = get_og_ip(qname)
                        json_out["src_ip"] = s_ip
                        json_out["tcp_opts"] = opts
                        json_out["tfo_set"] = bool("tfo" in opts)
                        json_out["tfo_info"] = get(tfo_info, line)
                        output_file.write(json.dumps(json_out) + '\n')
                        written_results += 1
                # For a regular query find the options in associated sSYN
                elif flags == 'P.' and args.keyword in qname:
                    for prev_ip, prev_opts in syn_packets.items():
                        if prev_ip == s_ip:
                            json_out = {key: None for key in json_keys}
                            json_out["original_ip"] = get_og_ip(qname)
                            json_out["src_ip"] = s_ip
                            json_out["tcp_opts"] = opts
                            json_out["tfo_set"] = bool("tfo" in opts)
                            json_out["tfo_info"] = get(tfo_info, line)
                            output_file.write(json.dumps(json_out) + '\n')
                            written_results += 1
                            del syn_packets[s_ip]
                            break
            except Exception as e:
                print(e)
                print(line)
                e.with_traceback()


