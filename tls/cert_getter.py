"""
Pulls SSL certificates for each IP in a list. Wraps around openssl command line calls.
Write results as .pem files to folder specified
"""
__author__ = "Jacob Davis as part of research at imaal.byu.edu"

import subprocess
import shlex
import multiprocessing as mp
from os import makedirs
from tqdm import tqdm
import argparse


def query(ip, path):
    """
    Queries the given IP for a TLS certificate and writes the certificate to the given path
    :param ip: the IP to get a certificate from
    :param path: the path to write the .pem file to
    :return: True if no errors
    """

    # Below reconstructs this command: echo "Q" | openssl s_client -connect {}:853 | openssl x509 -outform pem -out {}
    echo = subprocess.Popen(shlex.split("echo \"Q\""), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    openssl_connect = subprocess.Popen(shlex.split("openssl s_client -connect {}:853".format(ip)), stdin=echo.stdout,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    openssl_write = subprocess.Popen(shlex.split("openssl x509 -outform pem -out {}".format(path)),
                                     stdin=openssl_connect.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    out, err = openssl_write.communicate()
    if err != "":
        return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Running a series of openssl certificate queries on a list of IPs")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="Directory to write results to", default='results/')
    parser.add_argument('-n', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    args = parser.parse_args()

    result_folder = args.output.rstrip('/') + '/'
    makedirs(result_folder, exist_ok=True)
    ip_cname_file = open(args.input)
    data = []
    for line in ip_cname_file:
        ip = line.strip('\n')
        path = result_folder + ip.replace('.', '_') + '.pem'
        if "." not in ip:
            continue
        data.append((ip, path))

    threads = min(args.num_threads, len(data))

    print("Beginning the {} queries using {} threads.".format(len(data), threads))
    with mp.Pool(processes=threads) as p:
        try:
            res = tqdm(p.starmap(query, data), total=len(data))
            if not res:
                print()
        except KeyboardInterrupt:
            p.terminate()
            p.join()
            print("Exiting early from queries. Current results will still be written")
    print("Queries finished. ")

