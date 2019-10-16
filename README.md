#### Purpose
This repository provides source code for the 
"DNS Privacy in Practice and Preparation" accepted at CoNEXT'19 and is 
meant to aid reproducibility of the study.

#### Code
All code was written for `python3`.

There is a common pattern of `*_issuer.py` and `*_parser.py` files.
In these instances, the issuer was used to send queries and run a
tcpdump subprocess that was recording incoming queries. The parser was
then run on the pcap. This was necessary in cases where sequential 
packets needed to be grouped (such as TFO) or cases where the incoming
pcap was recorded from an authoritative server over an interface.

#### Dependencies
Some code relies on a fork of `dnspython` which provides
added support for DoT and DoH. This fork can be found 
[here](https://github.com/byu-imaal/dnspython)

All other dependencies are publicly available.

