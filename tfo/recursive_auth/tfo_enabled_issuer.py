"""
Checks to see if resolvers send data in their SYN
Issues queries to a list of recursive resolvers passed in through a file.
Does so in parallel. Also starts tcpdump listening on `INTERFACE` and captures a full pcap while queries are issued

Sends 2 queries, labeled 1.x and 2.x respectively. This ensures that there is a valid cookie
"""

__author__ = "Jacob Davis as part of research at imaal.byu.edu"


import base64
import socket
import struct
import multiprocessing as mp
import subprocess
import shlex
import argparse
import time
import dns.resolver
from tqdm import tqdm

class LabelUtil:

    @classmethod
    def timestamp_to_label(cls, timestamp):
        return base64.b32encode(struct.pack('>I', timestamp))[:-1].lower().decode("utf-8")

    @classmethod
    def ip_to_label(cls, ip):
        if ':' in ip:
            return base64.b32encode(socket.inet_pton(socket.AF_INET6, ip))[:-6].lower().decode("utf-8")
        else:
            return base64.b32encode(socket.inet_pton(socket.AF_INET, ip))[:-1].lower().decode("utf-8")


# some domain name that can be monitored and that returns a TXT over 512 bytes forcing
# a TCP connection to be used by the resolved
suffix = "XXX"

def query(qname, resolver):
    try:
        answers = resolver.query(qname, "TXT")
    except Exception as ex:
        return type(ex).__name__
    if len(answers) > 0:
        return "ANS"
    else:
        return "NO ANS"


def double_query(tup):
    (qname_key, resolver_ip) = tup
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [resolver_ip]
    resolver.lifetime = 3
    resolver.timeout = 3

    qname = "{}.{}.{}.{}.".format(LabelUtil.timestamp_to_label(int(time.time())), LabelUtil.ip_to_label(resolver_ip),
                                  qname_key, suffix)

    results = ["{}, {}, {}".format(resolver_ip, qname, query("1." + qname, resolver))]
    time.sleep(1)
    results.append("{}, {}, {}".format(resolver_ip, qname, query("2." + qname, resolver)))
    return results


def main():

    parser = argparse.ArgumentParser(description="Runs a series of queries to resolvers and captures responses to pcap."
                                                 "Run with python3.")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('keyword', help="keyword for URL to query for.")
    parser.add_argument('output', help="pcap to write to")
    parser.add_argument('-i', '--interface', help="interface tcpdump should listen on. Default is INTERFACE",
                        default="INTERFACE")
    parser.add_argument('-l', '--logfile', help="Log file to write results of queries to",
                        default="query_issue_log-{}.txt".format(time.time()))
    parser.add_argument('-n', '--numthreads', help="Number of threads to execute queries", default=1, type=int)
    parser_args = parser.parse_args()

    with open(parser_args.input, 'r') as resolver_ips_file:
        resolver_ips = [ip.strip() for ip in resolver_ips_file.readlines()]
        if not resolver_ips[0][0].isdecimal():
            resolver_ips = resolver_ips[1:]

    num_threads = min(len(resolver_ips), int(parser_args.numthreads))
    args = [(parser_args.keyword, resolver_ip) for resolver_ip in resolver_ips]

    # filter to tcp syn packets on dns ports
    tcpdump_filter = "(tcp port 53 or port 853) and (tcp[tcpflags] & tcp-syn != 0)"
    tcpdump = subprocess.Popen(shlex.split("sudo tcpdump -nSUi {} '{}' -w {}"
                                           .format(parser_args.interface, tcpdump_filter, parser_args.output)), stdout=subprocess.PIPE)
    try:
        time.sleep(5)
        print("Starting {} queries with {} threads".format(len(resolver_ips), num_threads))
        with open(parser_args.logfile, 'w') as log:
            with mp.Pool(processes=num_threads) as p:
                for result in tqdm(p.imap_unordered(double_query, args), total=len(args)):
                    log.write('\n'.join(result) + '\n')

        end_delay(30)
    except KeyboardInterrupt:
        print("Exiting once tcpdump finishes")
    tcpdump.terminate()
    tcpdump.wait()


def end_delay(secs):
    print(
        "finished queries. Waiting {} seconds to exit to prevent premature death of my child tcpdump".format(secs))
    for _ in tqdm(range(secs), total=secs, bar_format="Countdown: {n_fmt} |{bar}|"):
        time.sleep(1)


if __name__ == '__main__':
    main()
