#!/usr/bin/env python3

import argparse
from string import Template
import os
from datetime import datetime, timedelta

import packetfile
import rot13cbc

TIME_FORMAT = "%a, %d %b %Y %H:%M:%S GMT"
START_TIME = datetime.now()

request_template = Template("""GET /nonexistent/$suffix HTTP/1.1
Host: localhost:5000
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.8
Cookie: session=$cookie
""")

response_template = Template("""HTTP/1.0 404 NOT FOUND
Content-Type: text/html
Content-Length: 233
Server: Werkzeug/0.12.2 Python/3.5.2
Date: $date
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server.</p>
""")


def make_unique_request(index: int, cookie: str):
    return request_template.substitute(
        suffix="{:010d}".format(index),
        cookie=cookie)


def make_unique_response(index: int):
    cur_time = START_TIME + timedelta(seconds=index)
    formatted_time = cur_time.strftime(TIME_FORMAT)
    return response_template.substitute(date=formatted_time)


def encrypt(plain, iv):
    Rot13 = rot13cbc.Rot13cbc(len(iv), iv)
    return Rot13.encrypt(plain)


def generate_req_and_res(index: int, cookie: str):
    return (make_unique_request(index, cookie),  make_unique_response(index))


def generate_n_rounds(count, cookie):
    roundTrips = []
    for i in range(count):
        roundTrips.append(generate_req_and_res(i, cookie))

    return roundTrips


def encrypt_round(round_trip, block_size_bytes):
    req = round_trip[0]
    req_iv = os.urandom(block_size_bytes)
    req_encrypted = encrypt(req, req_iv)

    res = round_trip[1]
    res_iv = os.urandom(block_size_bytes)
    res_encrypted = encrypt(res, res_iv)

    return {
        "request": {
            "cipher": req_encrypted,
            "plain_length": len(req),
            "iv": req_iv,
        },
        "response": {
            "cipher": res_encrypted,
            "plain_length": len(res),
            "iv": res_iv
        }
    }

def format_cookie(cookie: str):
    # truncate to 32 characters and pad to 32 characters if smaller
    return "{:32s}".format(cookie[0:32])

def main(count: int, file: str, cookie: str, block_size_bytes: int):
    rounds = generate_n_rounds(count, cookie)
    encrypted = [encrypt_round(r, block_size_bytes) for r in rounds]

    packetfile.write_packets(encrypted, file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate N encrypted packets')
    parser.add_argument('file', type=str,
                        help="File to write encrypted packets to (in python pickle format)")

    parser.add_argument('--count', metavar='N', type=int, default=20,
                        help="Number of requests to send (in 1000s). Defaults to 20 to create 20k requests")
    parser.add_argument('--cookie', type=str, default="DEADBEEF-CAFE-FADE-FEED-DEADBEEF",
                        help="The value of the cookie written in each request. Will be truncated/padded to 32 chars")

    parser.add_argument('--block-size', type=int, default=4,
                        help="Block size in bytes. Defaults to 4 bytes for 32 bit block.")
    args = parser.parse_args()

    cookie = format_cookie(args.cookie)

    main(args.count*1000, args.file, cookie, args.block_size)
