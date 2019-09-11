"""
Script for querying a list of DNS resolvers over UDP/TCP/TLS.
Reads in IPs or domains from a file and queries each in parallel.
Writes responses as a summary in json.
"""

__author__ = "Jacob Davis as part of research at imaal.byu.edu"

import multiprocessing as mp
from tqdm import tqdm
import argparse
import json
import sys
import dns.resolver  # These are from our modified dnspython in imaal
import dns.exception

""" Constants across all queries in a run """
transport_type = "udp"
prefix = ""
json_keys = ["target", "transport", "got_response", "response", "error"]
base_domain = "XXX"  # domain name to query for


def check_dnspython():
    """
    ensures dnspython has the modified code that accepts a transport type.
    """
    if "transport" not in dns.resolver.query.__code__.co_varnames:
        print("Not using modified dnspython with tls support")
        exit(1)


def query(target):
    """
    Queries the given IP using dnspython
    :param target: the IP of the DNS server to query
    :return: a python dict summarizing the results following the format of `json_keys`
    """
    target = target.strip('\n')
    json_response = {key: None for key in json_keys}
    json_response["target"] = target
    json_response["transport"] = transport_type

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [target]
    resolver.port = (853 if transport_type == "tls" else 53)

    try:
        answers = resolver.query("{}.{}.".format(prefix, base_domain), "A", transport=transport_type, lifetime=3)
    except Exception as ex:
        # if it's any of these errors then it was at least responsive
        if any([isinstance(ex, e) for e in [dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                                            dns.resolver.NoAnswer, dns.resolver.NotAbsolute]]):
            json_response["got_response"] = True
        json_response["error"] = type(ex).__name__
        return json_response

    if len(answers) > 0:
        json_response["got_response"] = True
        json_response["response"] = str(answers[0])
    else:
        json_response["got_response"] = False

    return json_response


def main(args):
    global transport_type, prefix
    parser = argparse.ArgumentParser(description="Running a series of dns queries on a list of IPs")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="Output file to write results to")
    parser.add_argument('-n', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    parser.add_argument('-t', '--type', help="Type of communication e.g. tcp or tls. Leave off for udp", default='')
    parser.add_argument('-p', '--position_bar', help="The position of the tqdm progress bar. Used when running multiple"
                                                     "scripts at once. Default is 0", type=int, default=0)
    parser.add_argument('-q', '--query_prefix',
                        help="Query prefix to use. Default is <transport_support>.{}".format(base_domain),
                        default="transport_support")
    args = parser.parse_args(args)

    check_dnspython()

    in_file = open(args.input)
    targets = in_file.readlines()
    if not targets[0][0].isdecimal():
        targets = targets[1:]
    in_file.close()

    prefix = args.query_prefix.strip('.')
    transport_type = ('udp' if len(args.type) == 0 else args.type).lower()

    threads = min(args.num_threads, len(targets))

    with open(args.output, 'w') as output_file:
        with mp.Pool(processes=threads) as p:
            try:
                for result in tqdm(p.imap_unordered(query, targets), total=len(targets),
                                   desc="{} ({} threads)".format(transport_type, threads), position=args.position_bar):
                    output_file.write(json.dumps(result) + '\n')
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Exiting early from queries. Current results will still be written")


if __name__ == "__main__":
    main(sys.argv[1:])
