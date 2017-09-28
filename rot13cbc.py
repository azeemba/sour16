#!env python

class Rot13cbc:
    """Not true Rot13. Really its (x+13)%255 in CBC mode"""

    def __init__(self, block_size_bytes: int, iv: bytes):
        self.blockSizeBytes = block_size_bytes
        self.iv = iv
        assert self.blockSizeBytes == len(self.iv)

    def _byteRot13En(self, b):
        return (b + 13) % 256

    def _byteRot13Dec(self, b):
        return (b - 13) % 256

    def encrypt(self, plain: str) -> [bytes]:
        plain = plain.encode() # encode to binary

        length = len(plain)
        blocks = []
        block = self.iv
        for i in range(0, length, self.blockSizeBytes):
            prev_block = block
            block = bytearray()
            for j in range(0, self.blockSizeBytes):
                index = i + j
                if index < length:
                    block.append(self._byteRot13En(plain[index] ^ prev_block[j]))

            blocks.append(bytes(block))

        return blocks

    def decrypt(self, cypher: [bytes]):
        blocks = []

        prevBlock = self.iv
        for encBytes in cypher:
            decrypted = bytearray()
            for i in range(len(encBytes)):
                b = encBytes[i]
                decrypted.append(self._byteRot13Dec(b) ^ prevBlock[i])

            blocks.append(bytes(decrypted))
            prevBlock = encBytes

        return blocks


if __name__ == "__main__":
    r = Rot13cbc(4, 'ABCD'.encode())
    e = r.encrypt("How are you?")
    print("Encrypted string: ", e)
    d = r.decrypt(e)
    print("Decrypted string: ", d)
