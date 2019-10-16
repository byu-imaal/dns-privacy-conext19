import argparse
from os import listdir
import re
import json
from tqdm import tqdm

TFO_OPT = "tfo_opt"
NTFO_OPT = "no_tfo_opt"
SYN_DATA = "syn_data"
NSYN_DATA = "syn_only"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Combines repeated IPs in data")
    parser.add_argument('input', help="Input directory containing results for different servers")
    parser.add_argument('output', help="File to write results to")
    args = parser.parse_args()

    results = {}
    files = listdir(args.input)
    for file in tqdm(files, total=len(files), desc="Combining {} files".format(len(files))):
        path = "/{}/{}".format(args.input.strip('/'), file)
        with open(path, 'r') as in_file:
            lines = in_file.readlines()
            for line in lines:
                decoded = json.loads(line)
                ip = decoded["ip"]
                if ip not in results.keys():
                    results[ip] = decoded
                else:
                    results[ip][TFO_OPT] += decoded[TFO_OPT]
                    results[ip][NTFO_OPT] += decoded[NTFO_OPT]
                    results[ip][SYN_DATA] += decoded[SYN_DATA]
                    results[ip][NSYN_DATA] += decoded[NSYN_DATA]

    with open(args.output, 'w') as out:
        for key, val in results.items():
            out.write(json.dumps(val) + '\n')