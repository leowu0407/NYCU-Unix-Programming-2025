#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang

import sys
from pwn import *
from solpow import solve_pow
import zlib

if len(sys.argv) > 1:
    ## for remote access
    r = remote('up.zoolab.org', 10155)
    solve_pow(r)
else:
    ## for local testing
    r = process('./guess.dist.py', shell=False)


def decode_msg(msg):
    msg = base64.b64decode(msg)
    msg = zlib.decompress(msg[4:]).decode()
    return msg

msg = r.recvline()
print(decode_msg(msg))

msg = r.recvline()
print(decode_msg(msg))


r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
