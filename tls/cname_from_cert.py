import argparse
import M2Crypto
from os import listdir
import re

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Iterates over pem certs extracting cnames")
    parser.add_argument('input', help="Input directory containing pem certs")
    parser.add_argument('output', help="File to write results to", default='cnames.txt')
    args = parser.parse_args()

    results = {}
    for file in listdir(args.input):

        path = "/{}/{}".format(args.input.strip('/'), file)
        ip = file.split('.')[0].replace('_', '.')
        x509 = M2Crypto.X509.load_cert(path, M2Crypto.X509.FORMAT_PEM)
        subject = x509.get_subject().as_text()
        cname = re.search('(?<=CN=)(.+?)(?=$)', subject).group(1)

        if cname not in results.keys():
            results[cname] = []
        results[cname].append(ip)

    with open(args.output, 'w') as output:
        output.write("CNAME, #IPs, IPs\n")
        for cname in results:
            output.write("{}, {}, {}\n".format(cname, len(results[cname]), ', '.join(sorted(results[cname]))))
