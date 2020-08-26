#!/usr/bin/env python3
# Author: Katie Sexton
# Tested on: UniFi Protect 1.13.4
# This script:
# - Parses UniFi Protect's server.js to obtain a list of API endpoints and associated
#   HTTP methods
# - Without first authenticating, sends a request to each endpoint / method
# - Based on the response, determines whether or not the endpoint was accessible
#   without authentication
# - Outputs any API errors indicating required fields for endpoints

import argparse
import http.client
import json
import ssl
import sys
import os.path
import time
import re

TIMEOUT = None
DEBUG = False

VALID_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE", "CONNECT", "POST", "PUT", "DELETE", "PATCH"]

TIMED_OUT = -1
ACCESSIBLE_OK = 200
AUTHENTICATION_ERROR = '{"error":"Unauthorized","type":"AuthenticationError"}'


def debug(message):
    if not DEBUG:
        return None
    print("[+] {}".format(message))


def cli_params():
    parser = argparse.ArgumentParser(
            description="Test UniFi Protect API endpoints to determine which can be accessed while unauthenticated.")
    parser.add_argument("-t", "--target",
                        metavar="target",
                        required=False,
                        default="localhost",
                        help="The target IP or hostname")
    parser.add_argument("-p", "--port",
                        metavar="port",
                        required=False,
                        default=7443,
                        help="The target UniFi Management Portal UI port")
    parser.add_argument("-n", "--no-ssl",
                        action="store_true",
                        default=False,
                        help="Disable SSL")
    parser.add_argument("-s", "--seconds-timeout",
                        metavar="seconds",
                        required=False,
                        default=30,
                        help="Timeout per request")
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
    pattern = '[^a-z][a-z]\.([a-z]+)\("(/[^"]+)",'
    endpoints = []
    with open(filepath) as fp:
        for line in fp:
            matches = re.findall(pattern, line)
            if not matches:
                continue
            for match in matches:
                method = match[0].upper()
                if method not in VALID_METHODS:
                    continue
                endpoint = match[1]
                if not endpoint.startswith("/api"):
                    endpoint = "/api{}".format(endpoint)
                endpoints.append((method, endpoint))
                debug("Found endpoint to test: {} {}".format(method, endpoint))
    return endpoints
    

def get_conn(host, port, use_ssl):
    """
    Connect to target host and port, using SSL unless SSL use has been disabled
    """
    debug("Getting connection to host {}, port {}".format(host, port))
    if use_ssl is False:
        return http.client.HTTPConnection(host, port)
    return http.client.HTTPSConnection(host, port, context=ssl.SSLContext())


def test_endpoint(conn, headers, method, endpoint):
    """
    Test passed endpoint using passed method and determine whether endpoint requires auth
    """
    debug("Trying: {} {}".format(method, endpoint))
    try:
        conn.request(method, endpoint, headers=headers)
    except OSError:
        exit("OSError sending to target port. Use --no-ssl or -n if target port is not an SSL port.")

    start = time.time()
    res = None
    while time.time() - start < TIMEOUT:
        try:
            res = conn.getresponse()
        except http.client.ResponseNotReady:
            continue
        except http.client.RemoteDisconnected:
            exit("Remote disconnected when getting response from target port. Do not use --no-ssl or -n if target port is an SSL port.")
        body = res.read().decode()
        break

    if not res:
        debug("Response to {} request for endpoint '{}' timed out after {} seconds".format(method, endpoint, TIMEOUT))
        return TIMED_OUT, None, None

    debug("Response: {} {}\n  {}".format(res.status, res.reason, body))
    return res.status, res.reason, body


def test_endpoints(host, port, use_ssl, endpoints):
    """
    Test each endpoint with its associated method and compile lists of endpoints that
    can and cannot be accessed without prior authentication
    """
    conn = get_conn(host, port, use_ssl)
    if not conn:
        sys.exit("Failed to connect to host {}, port {}".format(host, port))

    headers = {"Content-type": "application/json"}
    results = []
    for entry in endpoints:
        method, endpoint = entry
        try_endpoint = endpoint
        if ":" in endpoint:
            try_endpoint = re.sub(r":[a-zA-Z]+", "1", endpoint)
        try_endpoints = []
        if "(s)?" in try_endpoint:
            try_endpoints.append(try_endpoint.replace("(s)?","s"))
            try_endpoints.append(try_endpoint.replace("(s)?",""))
        else:
            try_endpoints = [try_endpoint]

        for try_endpoint in try_endpoints:
            status, reason, body = test_endpoint(conn, headers, method, try_endpoint)
            results.append({
                "status":status,
                "reason":reason,
                "body":body,
                "method":method,
                "endpoint":endpoint,
                "actual_endpoint":try_endpoint
            })

    conn.close()

    return results


def report_auth_required(login_required):
    print("\nThe following method / endpoint combinations require prior authentication:\n")
    if not len(login_required):
        print("  None found")
        return None
    for entry in login_required:
        endpoint = "{} ({})".format(entry["actual_endpoint"], entry["endpoint"]) \
                if entry["actual_endpoint"] != entry["endpoint"] else entry["endpoint"]
        print("  - {} {}".format(entry["method"], endpoint))


def report_auth_not_required(accessible_ok, accessible_error):
    print("\nThe following method / endpoint combinations do not require prior authentication:\n")
    all_accessible = accessible_ok + accessible_error
    if not len(all_accessible):
        print("  None found")
        return None
    for entry in all_accessible:
        endpoint = "{} ({})".format(entry["actual_endpoint"], entry["endpoint"]) \
                if entry["actual_endpoint"] != entry["endpoint"] else entry["endpoint"]
        print("  - {} {}".format(entry["method"], endpoint))

    if len(accessible_ok):
        print("\n  No data required for request:\n")
        for entry in accessible_ok:
            endpoint = "{} ({})".format(entry["actual_endpoint"], entry["endpoint"]) \
                    if entry["actual_endpoint"] != entry["endpoint"] else entry["endpoint"]
            print("    - {} {}".format(entry["method"], endpoint))

    if len(accessible_error):
        print("\n  Error indicates data is required for request:\n")
        for entry in accessible_error:
            endpoint = "{} ({})".format(entry["actual_endpoint"], entry["endpoint"]) \
                    if entry["actual_endpoint"] != entry["endpoint"] else entry["endpoint"]
            print("    - {} {}".format(entry["method"], endpoint))
            print("      {}\n".format(entry["body"]))


def report_unexpected(unexpected):
    print("\nThe following method / endpoint combinations returned unexpected responses:\n")
    for entry in unexpected:
        endpoint = "{} ({})".format(entry["actual_endpoint"], entry["endpoint"]) \
                if entry["actual_endpoint"] != entry["endpoint"] else entry["endpoint"]
        print("  - {} {}".format(entry["method"], endpoint))
        print("  {} {}".format(entry["status"], entry["reason"]))
        print("    {}".format(entry["body"]))


def report_timed_out(timed_out):
    print("\nRequest timed out for the following method / endpoint combinations:\n")
    for entry in timed_out:
        print("  - {} {}".format(entry["method"], entry["endpoint"]))


def report_results(results):
    accessible_ok = []
    accessible_error = []
    login_required = []
    timed_out = []
    unexpected = []
    for result in results:
        if result["status"] == ACCESSIBLE_OK:
            accessible_ok.append(result)
        elif result["status"] == TIMED_OUT:
            timed_out.append(result)
        elif result["body"] == AUTHENTICATION_ERROR:
            login_required.append(result)
        elif result["body"].startswith('{"') and result["body"].endswith('}'):
            accessible_error.append(result)
        else:
            unexpected.append(result)

    report_auth_required(login_required)
    report_auth_not_required(accessible_ok, accessible_error)
    if len(unexpected):
        report_unexpected(unexpected)
    if len(timed_out):
        report_timed_out(timed_out)


def main():
    """
    Parse CLI parameters, build list of usernames to test, call functions to test usernames, and output results
    """
    global TIMEOUT, DEBUG
    parser = cli_params()
    args = parser.parse_args()

    accept = input("\nWARNING: TEST AT YOUR OWN RISK.\n\nTesting all APIs may result in unexpected impacts to target device including data loss.\nRun test? [y/n]: ")
    if accept != "y":
        exit(0)

    if args.debug:
        DEBUG = True

    if not os.path.isfile(args.file):
        sys.exit("File {} does not exist".format(args.file))
    print("\nParsing endpoints from {}".format(args.file))
    endpoints = find_endpoints(args.file)

    if not len(endpoints):
        sys.exit("No endpoints found in file {}".format(args.file))

    use_ssl = True
    if args.no_ssl:
        use_ssl = False

    TIMEOUT = args.seconds_timeout

    print("\nTesting endpoints...\n(run with -d to monitor progress)")
    results = test_endpoints(args.target, args.port, use_ssl, endpoints)
    report_results(results)

    print()

main()
