"""
Checks which versions of TLS are supported by each IP in a file.
This is done by wrapping around an openssl command.
Note that openssl 1.1.1 is required since this script tests for TLSv1.3.
In addition, the script checks if a session ticket is included by the server and if
resumption is possible. This is determined by using -reconnect in the openssl command.
"""
__author__ = "Jacob Davis as part of research at imaal.byu.edu"

import subprocess
import shlex
import multiprocessing as mp
from tqdm import tqdm
import argparse
import re
import json


json_keys = ["ip", "tls1", "tls1_res", "tls1_tick",
                   "tls1_1", "tls1_1_res", "tls1_1_tick",
                   "tls1_2", "tls1_2_res", "tls1_2_tick",
                   "tls1_3", "tls1_3_tick", "had_timeout"]

tls_map = ["tls1", "tls1_1", "tls1_2", "tls1_3"]


def query(ip):
    """
    Queries the given IP over all of the tls versions listed in `tls_map`
    :param ip: the IP to query
    :return: A json dictionary of the format `json_keys`
    """
    ip = ip.strip('.\n')
    # print(ip)
    json_response = {key: False for key in json_keys}
    json_response["had_timeout"] = ""
    json_response["ip"] = ip
    # print(json_response)
    # print(tls_map)
    for arg in tls_map:
        # print("{}".format(arg, flush=True))
        try:
            echo = subprocess.Popen(shlex.split("echo \"Q\""), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            openssl_connect = subprocess.Popen(shlex.split("openssl s_client -connect {}:853 -{} -reconnect"
                                                           .format(ip, arg)), stdin=echo.stdout, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, universal_newlines=True)
            out, err = openssl_connect.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            json_response["had_timeout"] += "{} ".format(arg)
            continue
        if re.search("BEGIN CERTIFICATE", out):  # make sure we got a certificate
            json_response[arg] = True
        if re.search("Reused,", out) and arg != "tls1_3":
            json_response["{}_res".format(arg)] = True
        if re.search("TLS session ticket:", out) and arg != "tls1_3":
            json_response["{}_tick".format(arg)] = True

    return json_response


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Running a series of openssl certificate queries on a list of IPs")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="Directory to write results to", default='results/')
    parser.add_argument('-n', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    args = parser.parse_args()

    # result_folder = args.output.rstrip('/') + '/'
    # makedirs(result_folder, exist_ok=True)
    with open(args.input) as ip_file:
        ips = ip_file.readlines()
        if "." not in ips[0]:
            ips = ips[1:]

    threads = min(args.num_threads, len(ips))
    results = []
    print("Beginning the {} queries using {} threads.".format(len(ips), threads))
    with mp.Pool(processes=threads) as p:
        try:
            results.extend(tqdm(p.imap_unordered(query, ips), total=len(ips)))

        except KeyboardInterrupt:
            p.terminate()
            p.join()
            print("Exiting early from queries. Current results will still be written")
    # print(results)
    with open(args.output, 'w') as output_file:
        for result in results:
            output_file.write(json.dumps(result) + '\n')
    print("Queries finished. ")

