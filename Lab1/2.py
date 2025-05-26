from pwn import *
r = process('read Z; echo You got $Z', shell=True)
r.sendline(b'AAA')
r.interactive()
