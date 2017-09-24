#! env python

import argparse
from string import Template
import os
from datetime import datetime, timedelta
import pickle

import rot13cbc

BLOCK_SIZE_BYTES = 4

TIME_FORMAT = "%a, %d %b %Y %H:%M:%S GMT"
START_TIME = datetime.now()

REQUEST_COOKIE_INDEX = 376
request_template = Template("""GET /nonexistent/$suffix HTTP/1.1
Host: localhost:5000
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.8
Cookie: session=DEADBEEF-CAFE-FADE-FEED-DEADBEEF
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


def make_unique_request(index: int):
    return request_template.substitute(suffix="{:010d}".format(index))


def make_unique_response(index: int):
    cur_time = START_TIME + timedelta(seconds=index)
    formatted_time = cur_time.strftime(TIME_FORMAT)
    return response_template.substitute(date=formatted_time)


def encrypt(plain, iv):
    Rot13 = rot13cbc.Rot13cbc(BLOCK_SIZE_BYTES, iv)
    return Rot13.encrypt(plain)


def generate_req_and_res(index: int):
    return (make_unique_request(index),  make_unique_response(index))


def generate_n_rounds(count):
    roundTrips = []
    for i in range(count):
        roundTrips.append(generate_req_and_res(i))

    return roundTrips


def encrypt_round(round_trip):
    req = round_trip[0]
    req_iv = os.urandom(BLOCK_SIZE_BYTES)
    req_encrypted = encrypt(req, req_iv)

    res = round_trip[1]
    res_iv = os.urandom(BLOCK_SIZE_BYTES)
    res_encrypted = encrypt(res, res_iv)

    return {
        "request": {
            "cipher": req_encrypted,
            "iv": req_iv,
        },
        "response": {
            "cipher": res_encrypted,
            "iv": res_iv
        }
    }


def main(count: int, file: str):
    rounds = generate_n_rounds(count)
    encrypted = [encrypt_round(r) for r in rounds]

    with open(file, 'wb') as f:
        pickle.dump(encrypted, f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate N encrypted packets')
    parser.add_argument('count', metavar='N', type=int,
                        help="Number of requests to send. A good value is 20000")
    parser.add_argument('--file', '-f', type=str, required=True,
                        help="File to write packets to")

    args = parser.parse_args()

    main(args.count, args.file)
