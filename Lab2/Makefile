
obj-m     += cryptomod.o
ccflags-y += -DEXPORT_SYMTAB

all: crypto
	make -C ../dist/modulebuild M=$(PWD) modules

crypto: crypto.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f crypto
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp crypto cryptomod.ko ../rootfs/modules
	cp ../test_crypto ../rootfs
	cp ../fun.jpg.enc ../rootfs
