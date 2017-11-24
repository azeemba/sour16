sour16
======

This is a toy version of the sweet32 attack: https://sweet32.info/

The attack is an example of a birthday attack which exploits crypto algorithms
with small block sizes in CBC mode. The attack requires generation of a lot of
encrypted blocks with known plaintext. After the generation, identical
encrypted blocks can be identified and used to identify the plaintext value of
the blocks with unknown plaintext.

sour16 uses `rot13` as its base encryption algorithm. Though basically any
hashing/encryption algorithm with customizable block size and chained in CBC
mode would work here.

Similarly to sweet32, sour16 generates a lot of encrypted HTTP packets where
the only unknown is a cookie value. Then uses the attack to retrieve the cookie
value.

## Scripts

### Packet Generation: 

`generate_packets.py`: The script allows you to generate encrypted packets and
dump them to a file. It supports `-N` flag to change number of packets
generated (in the 1000s). It also allows configuration of the cookie value or
the block size.

Example command:

```
./generate_packets.py --count 30 --cookie "SECRET COOKIE" --block-size 4 30k-32bit.out
# creates a file called 30k-32bit.out
# creates 30,000 encrypted packets with a 4 bytes (32 bit) block size
# each packet has the cookie set to "SECRET COOKIE"
```

### Retrieving cookie by finding identical blocks

`sour16.py`: This is the script that executes the actual attack and requires a
file that is generated using the `generate_packets.py` script. Since the block
size can vary, the script needs to know the block size used for the encryption
as well.

Example command:

```
./sour16.py --block-size 4 30k-32bit.out
Retrieved the entire cookie! SECRET COOKIE
```

As shown above, the cookie was succesfully retrieved!

## Stats

`find_expected_packet_counts.py` runs many cycles of encrypt-decrypt for
varying block size to figure out how many packets are needed on average. The
numbers below are very course but give a rought idea of packet count as a
function of block size.

|Block size| Block size| Num Packets| File size| Block count|
|---|---|---|---|---|
|2 byte| 16 bits| 40 packets| 28KB| 28k blocks|
|3 byte| 24 bits| 1000 packets| 700KB| 364k blocks|
|4 byte| 32 bits| 12500 packets| 8.4MB| 2.8M blocks|
|5 byte| 40 bits| 250,000 packets| 174MB| 35M blocks|
