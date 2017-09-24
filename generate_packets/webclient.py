import argparse
from multiprocessing import Pool

import requests

HOST = "http://localhost:5000"
COOKIES = {}


def make_request(url: str, cookies: dict):
    headers = {
        "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/59.0.3071.115 Safari/537.36"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.8"
    }

    r = requests.get(url, headers=headers, cookies=cookies)

    return r

def url_request(url: str):
    make_request(url, COOKIES)

def generate_n_packets(count: int, concurrent: int) -> None:
    first_resp = make_request(HOST, {})
    COOKIES = first_resp.cookies
    count = count - 1  # We made one request already
    target = HOST + "/random"

    with Pool(concurrent) as pool:
        while count > 0:
            cur_count = min(count, concurrent)
            count -= cur_count

            urls = [target] * cur_count
            pool.map(url_request, urls)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate N packets by sending request to localhost')
    parser.add_argument('count', metavar='N', type=int, help="Number of requests to send")
    parser.add_argument('--concurrent', type=int, default=100, dest='concurrent',
                        help="Number of concurrent requests to send (default 100)")
    args = parser.parse_args()

    generate_n_packets(args.count, args.concurrent)
