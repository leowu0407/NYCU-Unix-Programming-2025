CC = gcc
CFLAGS = -Wall -Wextra -fPIC -g
LDFLAGS = -shared
RPATH = -Wl,-rpath=.

LIBRARY = libgotoku.so
EXEC = gotoku.local

OBJ = libgotoku_dummy.o gotoku.o

all: $(LIBRARY) $(EXEC)

$(LIBRARY): libgotoku_dummy.o
	$(CC) $(LDFLAGS) -o $@ $^

$(EXEC): gotoku.o $(LIBRARY)
	$(CC) $(CFLAGS) -o $@ gotoku.o -L. -lgotoku $(RPATH)

libgotoku_dummy.o: libgotoku_dummy.c libgotoku.h
	$(CC) $(CFLAGS) -c $< -o $@

gotoku.o: gotoku.c libgotoku.h
	$(CC) $(CFLAGS) -c $< -o $@
local:
	gcc -o local.so -shared -fPIC local.c -ldl
server:
	gcc -o server.so -shared -fPIC server.c -ldl
clean:
	rm -f $(OBJ) $(LIBRARY) $(EXEC)

