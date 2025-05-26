from pwn import *

r = remote('ipinfo.io', 80)
r.send(b"GET /ip HTTP/1.1\r\n")
r.send(b"Host: ipinfo.io\r\n")
r.send(b"User-Agent: curl/7.81.0\r\n")
r.send(b"Accept: */*\r\n")
r.send(b"Connection: close\r\n\r\n")

response = r.recvall()

ip_address = response.decode().split("\r\n")[-1]
print(ip_address)

r.close()

