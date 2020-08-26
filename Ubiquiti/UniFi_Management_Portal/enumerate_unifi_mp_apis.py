#!/usr/bin/env python3
# Author: Katie Sexton
# Tested on: UniFi Cloud Key Gen2 Plus firmware version 1.1.10
# This script parses UniFi Management Portal's ump.js and outputs a list of API
# endpoints and associated HTTP methods

import argparse
import json
import sys
import os.path
import time
import re


VALID_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE", "CONNECT", "POST", "PUT", "DELETE", "PATCH"]


def cli_params():
    parser = argparse.ArgumentParser(
            description="Enumerate UniFi Management Portal API endpoints.")
    parser.add_argument("-f", "--file",
                        metavar="file",
                        required=False,
                        default="/usr/share/unifi-management-portal/app/be/ump.js",
                        help="Path to ump.js")
    return parser


def find_endpoints(filepath):
    apps_pattern = 'const apps=\{([^}]+)\}'
    endpoint_pattern = 'app\.([a-z]+)\("(/api[^"]+)"'
    endpoints = []
    appname_endpoints = []
    appnames = []
    with open(filepath) as fp:
        for line in fp:
            if "const apps={" in line:
                match = re.search(apps_pattern, line)
                if match:
                    apps = match.group(1).split(',')
                    for app in apps:
                        app = app.split(':')
                        appname = app[0].replace('"','')
                        appnames.append(appname)
            matches = re.findall(endpoint_pattern, line)
            if not matches:
                continue
            for match in matches:
                method = match[0].upper()
                if method not in VALID_METHODS:
                    continue
                endpoint = match[1]
                if not endpoint.startswith("/api"):
                    endpoint = "/api/ump{}".format(endpoint)
                if ":appName" in endpoint:
                    appname_endpoints.append((method, endpoint))
                else:
                    endpoints.append((method, endpoint))
    if len(appname_endpoints):
        if not len(appnames):
            endpoints.extend(appname_endpoints)
        else:
            for appname in appnames:
                for entry in appname_endpoints:
                    method, endpoint = entry
                    endpoints.append((method, endpoint.replace(":appName", appname)))
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
