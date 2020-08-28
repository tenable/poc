#!/usr/bin/env python3
# Author: Katie Sexton
# Tested on: UniFi Protect 1.13.4
# This script parses UniFi Protect's server.js and outputs a list of API endpoints and
# associated HTTP methods

import argparse
import sys
import os.path
import time
import re


VALID_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE", "CONNECT", "POST", "PUT", "DELETE", "PATCH"]


def cli_params():
    parser = argparse.ArgumentParser(
            description="Enumerate UniFi Protect API endpoints.")
    parser.add_argument("-f", "--file",
                        metavar="file",
                        required=False,
                        default="/usr/share/unifi-protect/app/server.js",
                        help="Path to server.js")
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        default=False,
                        help="Enable debugging")
    return parser


def find_endpoints(filepath):
    endpoint_pattern = re.compile(r'[^a-z][a-z]\.([a-z]+)\("(/[^"]+)",')
    or_pattern = re.compile(r'(\(([a-zA-Z-]+)\|([a-zA-Z-]+)\))')

    endpoints = []
    with open(filepath) as fp:
        for line in fp:
            matches = endpoint_pattern.findall(line)
            if not matches:
                continue
            for match in matches:
                method = match[0].upper()
                if method not in VALID_METHODS:
                    continue
                endpoint = match[1]
                if not endpoint.startswith("/api"):
                    endpoint = "/api{}".format(endpoint)
                if "(s)?" in endpoint:
                    endpoints.append((method, endpoint.replace("(s)?","s")))
                    endpoints.append((method, endpoint.replace("(s)?","")))
                elif or_pattern.search(endpoint):
                    or_strs = or_pattern.findall(endpoint)
                    for or_str in or_strs:
                        endpoints.append((method, endpoint.replace(or_str[0], or_str[1])))
                        endpoints.append((method, endpoint.replace(or_str[0], or_str[2])))
                else:
                    endpoints.append((method, endpoint))
    return list(set(endpoints))


def print_endpoints(endpoints):
    for entry in sorted(endpoints):
        method, endpoint = entry
        print("{} {}".format(method, endpoint))


def main():
    """
    Enumerate and print API endpoints and associated methods
    """
    parser = cli_params()
    args = parser.parse_args()
    
    if not os.path.isfile(args.file):
        sys.exit("File {} does not exist".format(args.file))
    endpoints = find_endpoints(args.file)

    if not len(endpoints):
        sys.exit("No endpoints found in file {}".format(args.file))

    print_endpoints(endpoints)

    print()

main()
