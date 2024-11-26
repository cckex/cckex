#!/bin/python3

import socket
import argparse
from scapy.all import *

def main():
    # setup argument parser
    parser = argparse.ArgumentParser(
                prog = 'cckeydump.py',
                description='Reverse steganographic methods (which where applied to the network stream to hide data) to extract transmitted data')
    parser.add_argument('pcap_file', nargs=1, metavar='file', type=str,
                help='Captured traffic from which the transmitted data should be extracted')
    parser.add_argument('-rfttl', '--restore-full-ttl', action='store_true',
                help='Extract data hidden in the full ttl field.',
                required=False)
    parser.add_argument('-fsrc', '--filter-source', nargs=1, metavar='source-ip', type=str,
                help='Filter Pakets for specific source ip.',
                required=False)
    parser.add_argument('-v', '--verbose', action='store_true',
                help='Activate verbose output.',
                required=False)

    # parse and extract arguments
    args = parser.parse_args()

    pcapFilepath = args.pcap_file[0]

    sourceIp = None
    if args.filter_source != None: sourceIp = args.filter_source[0]

    # iterate over pakages and extract data
    data = bytearray()
    count = 0
    pcapPkgs = rdpcap(pcapFilepath)
    for pkg in pcapPkgs:
        try:
            if sourceIp != None and sourceIp != pkg['IP'].src:
                continue

            if args.verbose: print("[info] extracting data from pkg " + str(count))
            count += 1

            if(args.restore_full_ttl):
                data += bytearray([pkg.ttl])
                if args.verbose: print(str(pkg['IP'].src) + ": " + hex(pkg.ttl))
        except:
            None

    if args.verbose: print("[info] recovered data: " + data.hex())

    startCount = 0
    dataCount = 0
    type = 0
    extractedData = bytearray()
    for i in data:
        if dataCount == 0:
            if startCount == 2:
                extractedData = bytearray()
                dataCount = i
                continue

            if startCount == 0 and i == 0xff:
                startCount += 1
            elif startCount == 1 and (i == 0xff or i == 0xfe):
                startCount += 1
                if   i == 0xff: type = 1
                elif i == 0xfe: type = 2
            else:
                startCount = 0
        else:
            extractedData += bytearray([i])
            dataCount -= 1

            if dataCount == 0:
                if type == 1:
                    print(extractedData[0:8].hex() + " " + extractedData[8:40].hex() + " " + extractedData[40:56].hex())
                else:
                    print(extractedData[0:8].hex() + " " + extractedData[8:40].hex())
                startCount = 0



if __name__ == "__main__":
    main()
