.PHONY: all clean

all:
	@gcc -shared -fPIC -o libzpoline.so.1 1.c
	@gcc -shared -fPIC -o libzpoline.so.2 2.c -ldl -lbfd -lopcodes
	@gcc -shared -fPIC -o libzpoline.so 3.c -ldl -lbfd -lopcodes -g
	@gcc -shared -fPIC -o logger.so logger.c
ex1: libzpoline.so.1
	@LD_PRELOAD=./libzpoline.so.1 ./ex1
ex2-1: libzpoline.so.2
	@LD_PRELOAD=./libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}'
ex2-2: libzpoline.so.2
	@LD_PRELOAD=./libzpoline.so.2 cat ex2-2.txt
ex3: libzpoline.so libex3hook.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./libex3hook.so ./ex3
ex4-1: libzpoline.so logger.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so touch main.c
ex4-2: libzpoline.so logger.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cat /etc/hosts
ex5: libzpoline.so logger.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so wget http://www.google.com -q -t 1
ex6: libzpoline.so logger.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")'
hidden1-1: libzpoline.so logger.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cp ex3 '[vsyscall]'
hidden1-2: libzpoline.so logger.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so ./'[vsyscall]'
hidden2-s: libzpoline.so logger.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so nc -lkU /tmp/hidden3.sock
hidden2-c: libzpoline.so logger.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so nc -U /tmp/hidden3.sock
hidden3: libzpoline.so logger.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so bash -c 'curl -s file:///etc/hosts'
hidden4: libzpoline.so logger.so
	@LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("python3 -c '\''import os; os.system(\"id\")'\''")'
clean:
	@rm -f libzpoline.so* logger.so *.o index.html* main.c *vsyscall*

