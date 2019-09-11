"""
Used to send queries over DoH
Has support for both GET and POST as specified by RFC
Test method for using non-standard json methods
"""

__author__ = "Jacob Davis as part of research at imaal.byu.edu"


import requests
import base64
import dns.message
import dns.rdatatype
import argparse
import multiprocessing as mp
from tqdm import tqdm
import json


def create_query(url, record_type="A", b64=False):
    """
    Creates a DNS query in wire format. Can be encoded in base64 for use in GET method
    :param url: the url to create a query for e.g. example.com
    :param record_type: the desired record type in string format e.g. AAAA
    :param b64: If true will base64url encode the query
    :return: the dns message in wire format or a b64 string
    """
    message = dns.message.make_query(url, dns.rdatatype.from_text(record_type)).to_wire()
    if not b64:
        return message
    else:
        return base64.urlsafe_b64encode(message).decode('utf-8').strip("=")


def decode_b64_answer(data):
    """
    Decodes a base64 response into wire format
    :param data: the base64 response
    :return: a dns wire message
    """
    message = dns.message.from_wire(data)
    return message


def get_wire(resolver_url, query_name):
    """
    Official RFC method. Send a get request to resolver/dns-query with param dns={base64 encoded dns wire query}
    :param resolver_url: The resolver to query e.g. 1.1.1.1
    :param query_name: The query url e.g. example.com
    :return: a dns.message object received from the resolver
    """
    headers = {"accept": "application/dns-message"}
    payload = {"dns": create_query(query_name, b64=True)}
    url = "https://{}/dns-query".format( resolver_url)
    try:
        res = requests.get(url, params=payload, headers=headers, stream=True, timeout=10)
        return [a.to_text() for a in decode_b64_answer(res.content).answer]
    except Exception as e:
        return None


def post_wire(resolver_url, query_name):
    """
    Official RFC method. Send a post request with the body being a raw dns query in wire format
    :param resolver_url: The resolver to query e.g. 1.1.1.1
    :param query_name: The query url e.g. example.com
    :return: a dns.message object received from the resolver
    """
    query = create_query(query_name)
    headers = {"accept": "application/dns-message", "content-type": "application/dns-message",
               "content-length": str(len(query))}
    url = "https://{}/dns-query".format(resolver_url)
    try:
        res = requests.post(url, data=query, headers=headers, stream=True, timeout=10)
        return [a.to_text() for a in decode_b64_answer(res.content).answer]
    except Exception as e:
        return None


def get_json(resolver_url, query_name):
    """
    Not in RFC, but appears to be a common method. Send get with a param name={url}. Response in json
    :param resolver_url: The resolver to query e.g. 1.1.1.1
    :param query_name: The query url e.g. example.com
    :return: a json response from the resolver
    """
    headers = {"accept": "application/dns-json"}

    payload = {"name": query_name}
    if resolver_url in ["8.8.8.8", "8.8.4.4", "dns.google.com"]:  # Google requires dns.google.com and /resolve
        print("Google is special")
        url = "https://dns.google.com/resolve"
    else:
        url = "https://{}/dns-query".format(resolver_url)
    try:
        res = requests.get(url, params=payload, headers=headers, stream=True, timeout=10)
        return res.json()
    except Exception as e:
        return None


def test_resolver(resolver):
    """
    Tests the given resolver for both GET and POST
    :param resolver: the resolver to query e.g. 8.8.8.8
    :return: a dictionary of {resolver, got response from either, post response, get response}
    """
    resolver = resolver.strip('\n')
    query = "example.com"
    data = {"resolver": resolver, "got_res": False, "post_res": "", "get_res": ""}
    post = post_wire(resolver, query)
    get = get_wire(resolver, query)
    if post is not None:
        data["post_res"] = post
        data["got_res"] = True
    if get is not None:
        data["get_res"] = get
        data["got_res"] = True
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Running a series of doh tests")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="Output file to write results to")
    parser.add_argument('-n', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    args = parser.parse_args()

    in_file = open(args.input)
    targets = in_file.readlines()
    in_file.close()
    if "." not in targets[0]:
        targets = targets[1:]

    threads = min(args.num_threads, len(targets))

    results = []
    print("Beginning the {} queries using {} threads.".format(len(targets), threads))

    with open(args.output, 'w') as output_file:
        with mp.Pool(processes=threads) as p:
            try:
                for result in tqdm(p.imap_unordered(test_resolver, targets), total=len(targets)):
                    output_file.write(json.dumps(result) + '\n')
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Exiting early from queries. Current results will still be written")

