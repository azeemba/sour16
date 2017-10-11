#!/usr/bin/env python3

import argparse
from lib import packetfile
import math

"""Sour16 tries to do a birthday attack on 32 bit blocks.
We use the terrible rot13cbc algorithm for this attack.
"""

REQUEST_PLAIN_TEXT = """GET /nonexistent/?????????? HTTP/1.1
Host: localhost:5000
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.8
Cookie: session=????????????????????????????????
"""

RESPONSE_PLAIN_TEXT =  """HTTP/1.0 404 NOT FOUND
Content-Type: text/html
Content-Length: 233
Server: Werkzeug/0.12.2 Python/3.5.2
Date: ?????????????????????????????
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server.</p>
"""


class Sour16Attack:

    def __init__(self, filename, block_size_bytes=4):
        self.known_plain_texts = {
            "request": self.split_text_into_blocks(REQUEST_PLAIN_TEXT, block_size_bytes),
            "response": self.split_text_into_blocks(RESPONSE_PLAIN_TEXT, block_size_bytes)
        }

        self.cookie_location = self.get_cookie_block_locations(block_size_bytes)
        self.index_location = self.get_request_id_block_locations(block_size_bytes)
        self.date_location = self.get_date_block_locations(block_size_bytes)

        self.round_trips = packetfile.read_packets(filename, block_size_bytes)

        self.encrypted_cookie_blocks = self._find_encrypted_cookie_blocks(self.round_trips)
        self.decrypted_cookie_blocks = [None] * (len(self.cookie_location))

    @staticmethod
    def split_text_into_blocks(text, block_size):
        return [text[i:i+block_size] for i in range(0, len(text), block_size)]

    @staticmethod
    def get_cookie_block_locations(block_size):
        start_index = 376
        end_index = 408
        return Sour16Attack.index_to_block_index(start_index, end_index, block_size)

    @staticmethod
    def get_request_id_block_locations(block_size):
        return Sour16Attack.index_to_block_index(17, 27, block_size)

    @staticmethod
    def get_date_block_locations(block_size):
        return Sour16Attack.index_to_block_index(110, 139, block_size)

    @staticmethod
    def index_to_block_index(start_index, end_index, block_size):
        start_block_index = start_index // block_size
        end_block_index = math.ceil(end_index/block_size)
        return range(start_block_index, end_block_index)

    def decrypt_cookie(self):
        encrypted_round_trips = self.round_trips

        for round_trip in encrypted_round_trips:
            request = round_trip['request']  # object has 'cipher' and 'iv'
            for i in range(len(request['cipher'])):
                if i in self.cookie_location or i in self.index_location:
                    continue

                if request['cipher'][i] in self.encrypted_cookie_blocks:
                    self._decrypt_block(request, self.known_plain_texts["request"], i)

            response = round_trip['response']
            for i in range(len(response['cipher'])):
                if i in self.date_location:
                    continue

                if response['cipher'][i] in self.encrypted_cookie_blocks:
                    self._decrypt_block(response, self.known_plain_texts["response"], i)

            if self._cookie_is_fully_decrypted():
                print("Retrieved the entire cookie!", "".join(self.decrypted_cookie_blocks))
                break

        if not self._cookie_is_fully_decrypted():
            print("Cookie was not fully decrypted. Partial result: ", self.decrypted_cookie_blocks)
            print("We need more blocks! Or more luck.")

        return self.decrypted_cookie_blocks

    def _cookie_is_fully_decrypted(self):
        return all([(x is not None) for x in self.decrypted_cookie_blocks])

    def _find_encrypted_cookie_blocks(self, encrypted_round_trips):
        encrypted = {}
        for round_trip in encrypted_round_trips:
            for location in self.cookie_location:
                block = round_trip['request']['cipher'][location]
                prev = round_trip['request']['cipher'][location - 1]
                encrypted[block] = {
                    "prev": prev,
                    "index": location - self.cookie_location[0],
                }

        return encrypted

    def _decrypt_block(self, ciphertext, plaintext, block_index):
        cipher = ciphertext['cipher']
        encrypted_cookie_blocks = self.encrypted_cookie_blocks
        plain_cookie = self.decrypted_cookie_blocks

        cookie_block = encrypted_cookie_blocks[cipher[block_index]]

        if plain_cookie[cookie_block["index"]] is not None:
            return

        plain = plaintext[block_index]
        # print("Collision found between encryption of block: '{}' and a cookie block index {}."
        #      .format(plain.replace("\n", "\\n"), cookie_block["index"]))

        if block_index != 0:
            prev = cipher[block_index - 1]
        else:
            prev = ciphertext['iv']

        cookie_prev = cookie_block["prev"]
        cookie_plain = self._find_plaintext_from_collision(plain, prev, cookie_prev)
        plain_cookie[cookie_block["index"]] = cookie_plain
        # print(plain, prev, cookie_prev, cipher[block_index], cookie_plain)

    @staticmethod
    def _find_plaintext_from_collision(plain, prev_cipher, prev_cookie):
        plain = plain.encode()
        final = []

        for i in range(len(plain)):
            final.append(chr(plain[i] ^ prev_cipher[i] ^ prev_cookie[i]))

        return ''.join(final)


def main(filename, block_size_bytes):
    attack = Sour16Attack(filename, block_size_bytes)
    return attack.decrypt_cookie()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze encrypted files to find cookie!')
    parser.add_argument('file', type=str,
                        help="File to read packets from. Use generate_packets.py to create the file")

    parser.add_argument('--block-size', type=int, default=4,
                        help="Block size in bytes. Defaults to 4 bytes for 32 bit block.")
    args = parser.parse_args()
    main(args.file, args.block_size)
