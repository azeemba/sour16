#! env python

import argparse
import pickle
from generate_packets import REQUEST_COOKIE_INDEX

"""Sour16 tries to do a birthday attack on 32 bit blocks.
We use the terrible rot13cbc algorithm for this attack.
"""

COOKIE_LOCATION = range(94, 103)
DATE_LOCATION = range(27, 35)
KNOWN_PLAIN_TEXTS = {
    "request": ['GET ', '/non', 'exis', 'tent', '/000', '0000', '000 ', 'HTTP', '/1.1', '\nHos',
                't: l', 'ocal', 'host', ':500', '0\nCo', 'nnec', 'tion', ': ke', 'ep-a', 'live',
                '\nUse', 'r-Ag', 'ent:', ' Moz', 'illa', '/5.0', ' (X1', '1; L', 'inux', ' x86',
                '_64)', ' App', 'leWe', 'bKit', '/537', '.36 ', '(KHT', 'ML, ', 'like', ' Gec',
                'ko) ', 'Chro', 'me/5', '9.0.', '3071', '.115', ' Saf', 'ari/', '537.', '36\nA',
                'ccep', 't: t', 'ext/', 'html', ',app', 'lica', 'tion', '/xht', 'ml+x', 'ml,a',
                'ppli', 'cati', 'on/x', 'ml;q', '=0.9', ',ima', 'ge/w', 'ebp,', 'imag', 'e/ap',
                'ng,*', '/*;q', '=0.8', '\nAcc', 'ept-', 'Enco', 'ding', ': gz', 'ip, ', 'defl',
                'ate,', ' br\n', 'Acce', 'pt-L', 'angu', 'age:', ' en-', 'US,e', 'n;q=', '0.8\n',
                'Cook', 'ie: ', 'sess', 'ion=', '????', '????', '????', '????', '????', '????', '????', '????', '\n'],
    "response": ['HTTP', '/1.0', ' 404', ' NOT', ' FOU', 'ND\nC', 'onte', 'nt-T', 'ype:', ' tex',
                't/ht', 'ml\nC', 'onte', 'nt-L', 'engt', 'h: 2', '33\nS', 'erve', 'r: W', 'erkz',
                'eug/', '0.12', '.2 P', 'ytho', 'n/3.', '5.2\n', 'Date', '????', '????', '????',
                '????', '????', '????', '????', '????', '<!DO', 'CTYP', 'E HT', 'ML P', 'UBLI',
                'C "-', '//W3', 'C//D', 'TD H', 'TML ', '3.2 ', 'Fina', 'l//E', 'N">\n', '<tit',
                'le>4', '04 N', 'ot F', 'ound', '</ti', 'tle>', '\n<h1', '>Not', ' Fou', 'nd</',
                'h1>\n', '<p>T', 'he r', 'eque', 'sted', ' URL', ' was', ' not', ' fou', 'nd o',
                'n th', 'e se', 'rver', '.</p', '>\n']
}

def find_encrypted_cookies(encrypted_round_trips):
    encrypted = {}
    for round_trip in encrypted_round_trips:
        for location in COOKIE_LOCATION:
            block = round_trip['request']['cipher'][location]
            prev = round_trip['request']['cipher'][location - 1]
            encrypted[block] = {
                "prev": prev,
                "index": location - COOKIE_LOCATION[0],
            }

    return encrypted

def find_plaintext_from_collision(plain, prev_cipher, prev_cookie):
    plain = plain.encode()
    final = []

    for i in range(len(plain)):
        final.append(chr(plain[i] ^ prev_cipher[i] ^ prev_cookie[i]))

    return ''.join(final)


def check_for_collision(round_trip, plaintext, i, cookie_blocks, plain_cookie):
    cipher = round_trip['cipher']
    if cipher[i] in cookie_blocks:
        cookie_block = cookie_blocks[cipher[i]]
        if plain_cookie[cookie_block["index"]] is not None:
            return
        print("Found a collision!", cipher[i], i)
        plain = KNOWN_PLAIN_TEXTS["request"][i]
        if i == 0:
            prev = round_trip['iv']
        else:
            prev = cipher[i-1]
        cookie_prev = cookie_block["prev"]
        cookie_plain = find_plaintext_from_collision(plain, prev, cookie_prev)
        plain_cookie[cookie_block["index"]] = cookie_plain


def decrypt_cookie(encrypted_round_trips, cookie_blocks):
    plain_cookie = [None]*(len(COOKIE_LOCATION) - 1)
    for round_trip in encrypted_round_trips:
        request = round_trip['request']
        for i in range(len(request['cipher'])):
            if i in COOKIE_LOCATION:
                continue
            check_for_collision(request, KNOWN_PLAIN_TEXTS["request"], i, cookie_blocks, plain_cookie)

        response = round_trip['response']
        for i in range(len(response['cipher'])):
            if i in DATE_LOCATION:
                continue
            check_for_collision(request, KNOWN_PLAIN_TEXTS["response"], i, cookie_blocks, plain_cookie)

        if all([(x is not None) for x in plain_cookie]):
            print("Found the entire cookie!", "".join(plain_cookie))
            break

    return plain_cookie


def main(filename):
    with open(filename, 'rb') as f:
        round_trips = pickle.load(f)

    cookie_blocks = find_encrypted_cookies(round_trips)
    decrypt_cookie(round_trips, cookie_blocks)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze encrypted files to find cookie!')
    parser.add_argument('file', type=str,
                        help="File to read packets from. Use generate_packets.py to create the file")

    args = parser.parse_args()

    main(args.file)
