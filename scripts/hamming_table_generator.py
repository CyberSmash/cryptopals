#!/usr/bin/env python3

for x in range(0, 256):
    distance = 0
    if x > 0 and x % 16 == 0:
        print("")
    while x > 0:
        bottom_val = x & 0x01
        if bottom_val > 0:
            distance += 1

        x = x >> 1
    
    print(f"{distance}, ", end='')

