import argparse
import subprocess
import shlex
import io
from tqdm import tqdm
import re
import json
import os

src_ip = re.compile(r'IP6? (.+)?\.\d+ >')
tcp_flags = re.compile(r'Flags \[(.+?)\]')
tcp_options = re.compile(r'options \[(.+?)\]')
length = re.compile(r'length (\d+)')


def get(pattern, line):
    try:
        return pattern.search(line).group(1)
    except:
        return ""


TFO_OPT = "tfo_opt"
NTFO_OPT = "no_tfo_opt"
SYN_DATA = "syn_data"
NSYN_DATA = "syn_only"


def inc_result(results, ip, key):
    """
    Increments the given key for the given IP.
    Example: inc_result(results, "1.1.1.1", TFO_OPT) increases the value of tfo_opt by 1 for 1.1.1.1
    :param results: the results dictionary
    :param ip: the ip
    :param key: the key e.g. TFO_OPT
    """
    if ip not in results:  # add new IP
        results[ip] = {TFO_OPT: 0, NTFO_OPT: 0, SYN_DATA: 0, NSYN_DATA: 0}
    results[ip][key] += 1


def run_on_file(it):
    for line in it:
        flags = get(tcp_flags, line)
        if flags == "S":
            ip = get(src_ip, line)
            tfo = bool("tfo" in get(tcp_options, line))
            if tfo:
                inc_result(results, ip, TFO_OPT)
            else:
                inc_result(results, ip, NTFO_OPT)
            pkt_len = get(length, line)
            if pkt_len.isdigit() and int(pkt_len) > 0:
                inc_result(results, ip, SYN_DATA)
            else:
                inc_result(results, ip, NSYN_DATA)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Collects TFO  data from a directory of pcap files")
    parser.add_argument('input', help="Input directory containg pcap files")
    parser.add_argument('output', help="File to write results to")
    args = parser.parse_args()

    all_files = []
    for root, dirs, files in os.walk(args.input):
        for file in files:
            if ".pcap" in file:
                all_files.append(os.path.join(root, file))

    pbar = tqdm(all_files, total=len(all_files), position=0, unit="files")
    results = {}

    for file in pbar:
        file_parts = file.split('/')
        gunzip = subprocess.Popen(shlex.split("gunzip -c {}".format(file)), stdout=subprocess.PIPE)
        tcpdump = subprocess.Popen(shlex.split("tcpdump  -lnr - "),
                                   stdin=gunzip.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        file_pbar = tqdm(io.TextIOWrapper(tcpdump.stdout, encoding="utf-8", errors="ignore"), position=1, unit='pkts')
        file_pbar.set_description_str("File: {}".format(
            '/'.join(file_parts[len(file_parts) - 2: len(file_parts)]).replace('.pcap.gz', '')))
        pbar.set_description_str("Results: {}".format(len(results)))

        run_on_file(file_pbar)

    with open(args.output, 'w') as output_file:
        for ip, vals in results.items():
            vals["ip"] = ip
            output_file.write(json.dumps(vals) + '\n')
