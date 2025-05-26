
CC64	= x86_64-linux-gnu-gcc
LD64	= x86_64-linux-gnu-ld
ASM64	= yasm -f elf64 -DYASM -D__x86_64__ -DPIC

CFLAGS	= -g -Wall -masm=intel -fno-stack-protector -fPIE

all:

%.o: %.c
	$(CC64) -c $(CFLAGS) $<

%.o: %.asm
	$(ASM64) $< -o $@

lib: libmini64.o libmini64-ext.o libmini.o
	ar rc libmini.a $^
	$(LD64) -pie -shared -z noexecstack -o libmini.so $^

test%: test%.o start.o lib
	#$(LD64) -pie -z noexecstack -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o $@ $< start.o -L. -lmini
	$(LD64) -static -pie -z noexecstack -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o $@ $< start.o -L. -lmini

clean:
	rm -f libmini.a libmini.so test0? test0?[ab]
