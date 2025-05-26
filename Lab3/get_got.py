from pwn import *
elf = ELF('./gotoku.local')
print("main =", elf.symbols['main'])
for s in [ f"gop_{i+1}" for i in range(1200)]:
   if s in elf.got:
      print("{},".format(elf.got[s]), end = ' ')

