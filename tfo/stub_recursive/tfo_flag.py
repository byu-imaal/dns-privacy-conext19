"""
Script that scans a list of IPs to see which support TCP Fast Open.
Done using scapy and by looking for the fast open option to be sent in the SYN ACK from the server.
Requires sudo to run scapy.
"""

__author__ = "Jacob Davis as part of research at imaal.byu.edu"

from scapy.all import sr1
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
import argparse
import multiprocessing as mp
from tqdm import tqdm
import os
import json

port = 53
ip6_src = None
TARGET = "target"
RESULT = "result"
json_keys = [TARGET, RESULT]


def query(ip):
    """
    queries an IP to see if TCP Fast Open option is set in SYN ACK
    :param ip: the ip to query. Uses `dport` constant
    :return: a tuple of ip, (True, False, Timeout). True if TFO set and Timeout if no response received
    """
    ip = ip.strip('\n')
    json_response = {key: None for key in json_keys}
    json_response[TARGET] = ip
    # sr1 - get single response, flags="S" - send SYN, options TFO - set fast open in options
    try:
        ip_layer = IP(dst=ip) if ":" not in ip else IPv6(dst=ip, src=ip6_src)
        # ip_layer.show()
        res = sr1(ip_layer / TCP(dport=port, flags="S", options=[('TFO', '')]), timeout=5, verbose=False)
        # res.show()
        if res is None:
            json_response[RESULT] = "Timeout"
        else:
            json_response[RESULT] = ('TFO' in dict(res[1].options))  # check if TFO is set in TCP response options
    except Exception as e:
        print(e)
        print(ip)
        json_response[RESULT] = "Can't resolve"
    finally:
        return json_response


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Running a series of scapy scans on a list of IPs to look for TFO")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="File to write results to", default='TFO_output.txt')
    parser.add_argument('-p', '--port', help="The port to run the scans on", default=53, type=int)
    parser.add_argument('-n', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    parser.add_argument('-6', '--ip6_src', help="Specifies the source address for ipv6 since scapy doesn't autofill")
    args = parser.parse_args()

    ip_file = open(args.input)
    ips = ip_file.readlines()
    if not ips[0][0].isdecimal():
        ips = ips[1:]
    ip_file.close()

    threads = min(args.num_threads, len(ips))
    port = args.port
    ip6_src = args.ip6_src

    summary = open(args.output, 'w')
    results = []
    print("Beginning the {} queries using {} threads. ".format(len(ips), threads))
    with open(args.output, 'w') as output_file:
        with mp.Pool(processes=threads) as p:
            try:
                for result in tqdm(p.imap_unordered(query, ips), total=len(ips)):
                    output_file.write(json.dumps(result) + '\n')
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Exiting early from queries. Current results will still be written")
    print("Queries finished. Writing results")

    os.chmod(args.output, 0o777)  # since script runs privileged, change file to be user writeable
