#!/usr/bin/env python3

import sour16
import time
import generate_packets
import tempfile
import os

def attempt_attack(block_size_bytes: int, packet_count: int):
    filename = 'sour16_packets'
    cookie_text = "00000000000000000000000000000000"
    directory = tempfile.gettempdir()
    filepath = os.path.join(directory, filename)

    generate_packets.main(packet_count, filepath, cookie_text, block_size_bytes)

    decrypted_cookie_blocks = sour16.main(filepath, block_size_bytes)

    percent_left = decrypted_cookie_blocks.count(None)/len(decrypted_cookie_blocks)

    os.remove(filepath)

    if percent_left == 0:
        decrypted_cookie  = "".join(decrypted_cookie_blocks)
        is_solved = cookie_text in decrypted_cookie
    else:
        is_solved = False

    return (is_solved, percent_left)

def repeat_multiple_attacks(block_size_bytes: int, packet_count: int, runs: int):
    percent_lefts = []

    start = time.time()
    for i in range(runs):
        (solved, percent) = attempt_attack(block_size_bytes, packet_count)
        percent_lefts.append(percent)

    return (sum(percent_lefts)/runs, (time.time()-start)/runs)

def find_expected_packet_count(block_size_bytes: int):
    print("Trying to find number of packets needed to attack block_size of ",
            block_size_bytes*8, " bits")
    runs = 10
    packet_count = 2
    solved = False
    runtime = None
    while not solved:
        print("Trying packet count: ", packet_count)
        (avg_percent_left, runtime) = repeat_multiple_attacks(
                block_size_bytes, packet_count, runs)

        print(avg_percent_left)
        solved = avg_percent_left < 0.01
        if not solved:
            multiplier = 5
            if avg_percent_left < 0.9:
                multiplier = 2
            packet_count = packet_count*multiplier

    return (packet_count, runtime)

def main():
    results = []
    results.append(find_expected_packet_count(2))
    results.append(find_expected_packet_count(3))
    results.append(find_expected_packet_count(4))
    # results.append(find_expected_packet_count(5))

    print(results)

if __name__ == "__main__":
    main()
