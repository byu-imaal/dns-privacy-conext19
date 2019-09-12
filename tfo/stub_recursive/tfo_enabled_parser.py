"""
Parses output from `tfo_enabled_issuer.py` looking for those who acknowledged data sent in a SYN with a valid cookie
"""

__author__ = "Jacob Davis as part of research at imaal.byu.edu"



import argparse
from scapy.all import *
import dns.query
import json
from tqdm import tqdm

tfo_qname = "tfo.XXX"

TARGET = "target"
TFO_QUERY_ACKED = "tfo_query_acked"
ACK = "rel_ack_num"
ERROR = "error"
P0F = "p0f"
json_keys = [TARGET, TFO_QUERY_ACKED, ACK, P0F, ERROR]


def make_query(qname):
    q = dns.message.make_query(qname, rdtype='A')
    wire = q.to_wire()
    msg = struct.pack(">H", len(wire)) + wire
    return msg


def get_ip(pckt, use_dst=False):
    if pckt.haslayer('IP'):
        return pckt['IP'].src if not use_dst else pckt['IP'].dst
    elif pckt.haslayer('IPv6'):
        return pckt['IPv6'].src if not use_dst else pckt['IP'].dst
    else:
        return None


def tfo_op_set(pkt):
    if pkt.haslayer('TCP'):
        for key, val in pkt["TCP"].options:
            if key == "TFO":
                return val
    return None


tfo_query_packets = []


def analyze(packet):
    # print(get_ip(packet))
    # print(packet.summary())
    # print("ANALYZE")
    if packet['TCP'].flags == "S" and packet.haslayer('DNSQR') and tfo_qname in packet['DNSQR'].qname.decode('utf-8'):  # TFO SYN + Data
        # print(packet['DNSQR'].qname.decode('utf-8'))
        # print("SYN + DATA")
        if tfo_op_set(packet) is not None:
            tfo_query_packets.append(packet)
            # print("PCKTS: {}".format(len(tfo_query_packets)))

    elif packet['TCP'].flags == "SA":  # SYN-ACK
        # print("SYN-ACK, SYNS={}".format(len(tfo_query_packets)))
        ip = get_ip(packet)
        for tfo_packet in tfo_query_packets:
            if get_ip(tfo_packet, True) == ip:
                msg_len = len(make_query(tfo_qname))
                json_response = {key: None for key in json_keys}
                json_response[TARGET] = ip
                ack = packet.ack - tfo_packet.seq
                json_response[TFO_QUERY_ACKED] = ack >= msg_len
                json_response[ACK] = ack
                json_response[P0F] = p0f(packet)
                tfo_query_packets.remove(tfo_packet)
                with open(args.output, 'a') as output_file:
                    # print("writing")
                    output_file.write(json.dumps(json_response) + '\n')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Running a series of scapy scans on a list of IPs to look for TFO")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="File to write results to. Default is stdout")
    args = parser.parse_args()
    load_module("p0f")


    total_packets = 0
    for _ in RawPcapReader(args.input):
        total_packets += 1

    syn_packets = {}
    for i, packet in tqdm(enumerate(PcapReader(args.input)), total=total_packets):
            analyze(packet)
