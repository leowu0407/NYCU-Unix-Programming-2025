#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang

import sys
from pwn import *
from solpow import solve_pow
import zlib
from itertools import permutations
from collections import defaultdict

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

def decode_a_b(msg):
    msg = base64.b64decode(msg)
    msg = zlib.decompress(msg[4:])
    msg = str(int.from_bytes(msg[0:4], 'big')) + chr(msg[4]) + str(int.from_bytes(msg[5:9], 'big')) + chr(msg[9])
    return msg

def encode_msg(msg):
    msg = msg.encode()
    msg = zlib.compress(msg)
    msg_len = len(msg)
    msg_len_bytes = struct.pack('<I', msg_len)
    msg = msg_len_bytes + msg
    msg = base64.b64encode(msg).decode().encode()
    return msg

def get_feedback(guess, answer):
    A = sum(1 for g, a in zip(guess, answer) if g == a)
    B = sum(1 for g in guess if g in answer) - A
    return A, B

def minimax_guess(possible_numbers):
    best_guess = None
    min_max_group = float('inf')
    
    for guess in possible_numbers:
        feedback_groups = defaultdict(int)
        for answer in possible_numbers:
            feedback = get_feedback(guess, answer)
            feedback_groups[feedback] += 1
        
        max_group_size = max(feedback_groups.values())
        
        if max_group_size < min_max_group:
            min_max_group = max_group_size
            best_guess = guess
    
    return best_guess

def solve_1a2b(answer):
        
        possible_numbers = [num for num in possible_numbers if get_feedback(guess, num) == (A, B)]
        guess = minimax_guess(possible_numbers)


msg = r.recvline()
print(decode_msg(msg))

msg = r.recvline()
print(decode_msg(msg))

possible_numbers = ["".join(p) for p in permutations("0123456789", 4)]

guess = "0123"

while True:
    r.sendline(encode_msg(guess))
    
    msg = r.recvline()
    msg = decode_a_b(msg)
    print(msg)

    if msg == "4A0B":
        break;

    A, B = int(msg[0]), int(msg[2])
    possible_numbers = [num for num in possible_numbers if get_feedback(guess, num) == (A, B)]
    guess = minimax_guess(possible_numbers)


    msg = r.recvline()
    print(decode_msg(msg))

    msg = r.recvline()
    print(decode_msg(msg))


msg = r.recvline()
print(decode_msg(msg))

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :

