#!/usr/bin/env python
from __future__ import print_function
import sys




if __name__ == '__main__':

    base_addr = int(sys.argv[1], 16)
    f = open(sys.argv[2], 'r') # gadgets

    for line in f.readlines():
        target_str, gadget = line.split(':')
        target_addr = int(target_str, 16)

        # check alignment
        if target_addr % 8 != 0:
            continue

        offset = (target_addr - base_addr) / 8
        print('offset =', (1 << 64) + offset)
        print('gadget =', gadget.strip())
        print('stack addr = %x' % (target_addr & 0xffffffff))
        break
