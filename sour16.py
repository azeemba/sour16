#! env python

import argparse
import pickle

"""Sour16 tries to do a birthday attack on 32 bit blocks.
We use the terrible rot13cbc algorithm for this attack.
"""

class Sour16Attack:

    COOKIE_LOCATION = range(94, 103)
    INDEX_LOCATION = range(4, 7)
    DATE_LOCATION = range(27, 35)
    KNOWN_PLAIN_TEXTS = {
        "request": ['GET ', '/non', 'exis', 'tent', '/???', '????', '??? ', 'HTTP', '/1.1', '\nHos',
                    't: l', 'ocal', 'host', ':500', '0\nCo', 'nnec', 'tion', ': ke', 'ep-a', 'live',
                    '\nUse', 'r-Ag', 'ent:', ' Moz', 'illa', '/5.0', ' (X1', '1; L', 'inux', ' x86',
                    '_64)', ' App', 'leWe', 'bKit', '/537', '.36 ', '(KHT', 'ML, ', 'like', ' Gec',
                    'ko) ', 'Chro', 'me/5', '9.0.', '3071', '.115', ' Saf', 'ari/', '537.', '36\nA',
                    'ccep', 't: t', 'ext/', 'html', ',app', 'lica', 'tion', '/xht', 'ml+x', 'ml,a',
                    'ppli', 'cati', 'on/x', 'ml;q', '=0.9', ',ima', 'ge/w', 'ebp,', 'imag', 'e/ap',
                    'ng,*', '/*;q', '=0.8', '\nAcc', 'ept-', 'Enco', 'ding', ': gz', 'ip, ', 'defl',
                    'ate,', ' br\n', 'Acce', 'pt-L', 'angu', 'age:', ' en-', 'US,e', 'n;q=', '0.8\n',
                    'Cook', 'ie: ', 'sess', 'ion=', '????', '????', '????', '????', '????', '????', '????', '????',
                    '\n'],
        "response": ['HTTP', '/1.0', ' 404', ' NOT', ' FOU', 'ND\nC', 'onte', 'nt-T', 'ype:', ' tex',
                     't/ht', 'ml\nC', 'onte', 'nt-L', 'engt', 'h: 2', '33\nS', 'erve', 'r: W', 'erkz',
                     'eug/', '0.12', '.2 P', 'ytho', 'n/3.', '5.2\n', 'Date', '????', '????', '????',
                     '????', '????', '????', '????', '????', '<!DO', 'CTYP', 'E HT', 'ML P', 'UBLI',
                     'C "-', '//W3', 'C//D', 'TD H', 'TML ', '3.2 ', 'Fina', 'l//E', 'N">\n', '<tit',
                     'le>4', '04 N', 'ot F', 'ound', '</ti', 'tle>', '\n<h1', '>Not', ' Fou', 'nd</',
                     'h1>\n', '<p>T', 'he r', 'eque', 'sted', ' URL', ' was', ' not', ' fou', 'nd o',
                     'n th', 'e se', 'rver', '.</p', '>\n']
    }

    def __init__(self, picked_filename):
        with open(picked_filename, 'rb') as f:
            self.round_trips = pickle.load(f)

        self.encrypted_cookie_blocks = self._find_encrypted_cookie_blocks(self.round_trips)
        print('Some Encrypted cookie blocks look like this: ', list(self.encrypted_cookie_blocks.keys())[:5])
        self.decrypted_cookie_blocks = [None] * (len(self.COOKIE_LOCATION) - 1)

    def decrypt_cookie(self):
        encrypted_round_trips = self.round_trips

        for round_trip in encrypted_round_trips:
            request = round_trip['request']  # object has 'cipher' and 'iv'
            for i in range(len(request['cipher'])):
                if i in self.COOKIE_LOCATION or i in self.INDEX_LOCATION:
                    continue

                if request['cipher'][i] in self.encrypted_cookie_blocks:
                    self._decrypt_block(request, self.KNOWN_PLAIN_TEXTS["request"], i)

            response = round_trip['response']
            for i in range(len(response['cipher'])):
                if i in self.DATE_LOCATION:
                    continue

                if response['cipher'][i] in self.encrypted_cookie_blocks:
                    self._decrypt_block(response, self.KNOWN_PLAIN_TEXTS["response"], i)

            if all([(x is not None) for x in self.decrypted_cookie_blocks]):
                print("Retrieved the entire cookie!", "".join(self.decrypted_cookie_blocks))
                break

        return self.decrypted_cookie_blocks

    def _find_encrypted_cookie_blocks(self, encrypted_round_trips):
        encrypted = {}
        for round_trip in encrypted_round_trips:
            for location in self.COOKIE_LOCATION:
                block = round_trip['request']['cipher'][location]
                prev = round_trip['request']['cipher'][location - 1]
                encrypted[block] = {
                    "prev": prev,
                    "index": location - self.COOKIE_LOCATION[0],
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


def main(filename):
    attack = Sour16Attack(filename)
    attack.decrypt_cookie()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze encrypted files to find cookie!')
    parser.add_argument('file', type=str,
                        help="File to read packets from. Use generate_packets.py to create the file")

    args = parser.parse_args()
    main(args.file)
