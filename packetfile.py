import contextlib


def write_packets(round_trips, filename):
    with contextlib.closing(_PacketFile(filename, 'w')) as f:
        f.write(round_trips)

def read_packets(filename, block_size):
    with contextlib.closing(_PacketFile(filename, 'r')) as f:
        return f.read(block_size)


INT_SIZE_BITS = 16  # bits
INT_SIZE_BYTES = INT_SIZE_BITS // 8


class _PacketFile:
    """Supports reading and writing a binary dump of packets"""

    def __init__(self, filename: str, mode: str):
        self.filename = filename
        if mode == 'w':
            self.mode = 'wb'
        else:
            self.mode = 'rb'

        self.handle = open(filename, self.mode)

    def write(self, round_trips):
        if self.mode != 'wb':
            return False

        for roundTrip in round_trips:
            self._write_trip(roundTrip["request"])
            self._write_trip(roundTrip["response"])

    def _write_trip(self, trip):
        # assume that IV is the same as block size.
        # otherwise we would have to document iv size
        iv = trip["iv"]
        self.handle.write(iv)

        blocks = trip["cipher"]
        combined_bytes = bytes().join(blocks)

        size = len(combined_bytes)
        self.handle.write(self._int2byte(size))
        self.handle.write(combined_bytes)
        self.handle.write(self._int2byte(trip["plain_length"]))


    def read(self, block_size):
        if self.mode != 'rb':
            return None

        round_trips = []
        while len(self.handle.peek(1)) != 0:
            request = self._read_trip(block_size)
            response = self._read_trip(block_size)
            round_trips.append({
                "request": request,
                "response": response
            })
        return round_trips

    def _read_trip(self, block_size):
        iv_bytes = self.handle.read(block_size)
        size_bytes = self.handle.read(INT_SIZE_BYTES)
        size = self._bytes2int(size_bytes)

        read_bytes = self.handle.read(size)
        if len(read_bytes) != size:
            raise RuntimeError("Input file is corrupted.")

        blocks = []
        for i in range(0, size, block_size):
            blocks.append(read_bytes[i:i + block_size])

        plain_length_bytes = self.handle.read(INT_SIZE_BYTES)
        plain_length = self._bytes2int(plain_length_bytes)

        return {
            "iv": iv_bytes,
            "cipher": blocks,
            "plain_length": plain_length
        }

    @staticmethod
    def _int2byte(num: int):
        if num > pow(2, INT_SIZE_BITS):
            raise OverflowError('Only supports a 2-byte int')

        if num < 0:
            raise OverflowError('Negative numbers not supported')

        return num.to_bytes(INT_SIZE_BYTES,
                            byteorder='big',
                            signed=False)

    @staticmethod
    def _bytes2int(num_in_bytes: bytearray) -> int:
        if len(num_in_bytes) != INT_SIZE_BYTES:
            raise ValueError("Not enough bytes.")

        return int.from_bytes(num_in_bytes,
                              byteorder='big',
                              signed=False)

    def close(self):
        if self.handle:
            self.handle.close()
