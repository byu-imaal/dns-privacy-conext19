"""
Checks that TFO actually works. Based on the following line in the RFC:
If the FastOpened flag is set, the packet acknowledges the SYN and data sequence.

The script checks for this for a given IP. Note that this script does not test for the TFO option to be set.
This script uses the kernel to handle details of TFO and the cookie itself
"""

__author__ = "Jacob Davis as part of research at imaal.byu.edu"


import socket
import dns.message
import struct
from time import sleep
import argparse
import os
import multiprocessing as mp
from tqdm import tqdm
import json
import subprocess
import shlex

req_qname = "creq.XXX"
tfo_qname = "tfo.XXX"

TARGET = "target"
TFO_QUERY_ACKED = "tfo_query_acked"
ACK = "rel_ack_num"
ERROR = "error"
json_keys = [TARGET, TFO_QUERY_ACKED, ACK, ERROR]


def make_query(qname):
    q = dns.message.make_query(qname, rdtype='A')
    wire = q.to_wire()
    msg = struct.pack(">H", len(wire)) + wire
    return msg


def send_tfo(target, qname="XXX", port=53):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_TCP, socket.TCP_FASTOPEN, 5)
    s.sendto(make_query(qname), socket.MSG_FASTOPEN, (target, port))
    s.settimeout(5)

    (l,) = struct.unpack(">H", s.recv(2))
    w = s.recv(l)
    return dns.message.from_wire(w)


def query(target):
    # print(target)
    try:
        send_tfo(target, qname=req_qname, port=custom_port)  # send one request to ensure we've got a cookie
        sleep(1)
    except Exception as e:
        pass
    try:
        send_tfo(target, qname=tfo_qname, port=custom_port)  # send another for test
        sleep(1)
    except Exception as e:
        pass
    return True


def end_delay(secs):
    print("finished queries. Waiting {} seconds to exit to prevent premature death of my child tcpdump".format(secs))
    for i in range(secs):
        print('.', end="", flush=True)
        sleep(1)
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Running a series of scapy scans on a list of IPs to look for TFO")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('pcap', help="the pcap to write to")
    parser.add_argument('output', help="File to write results to")
    parser.add_argument('-p', '--port', help="The port to run the scans on", default=53, type=int)
    parser.add_argument('-n', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    args = parser.parse_args()

    ip_file = open(args.input)
    ips = []
    for line in ip_file.readlines():
        if not line[0].isdecimal():
            continue
        ips.append(line.split(',')[0].strip())
    ip_file.close()

    open(args.output, 'w').close()  # clear output

    threads = min(args.num_threads, len(ips))
    custom_port = args.port

    print("Beginning the {} queries using {} threads. ".format(len(ips), threads))

    proc = subprocess.Popen(shlex.split("sudo tcpdump -nSU 'tcp port 53 or port 853' -w {}".format(args.pcap)),
                            stdout=subprocess.PIPE)
    try:
        sleep(5)

        with mp.Pool(processes=threads) as p:
            try:
                for result in tqdm(p.imap_unordered(query, ips), total=len(ips)):
                    sleep(.001)
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Exiting early from queries. Current results will still be written")
        print("Queries finished. Pausing before quiting")

        end_delay(30)
    except KeyboardInterrupt:
        print("Exiting once tcpdump finishes")
    proc.wait()
    os.chmod(args.output, 0o777)  # since script runs privileged, change file to be user writeable





