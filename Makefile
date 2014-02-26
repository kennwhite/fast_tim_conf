all:
	gcc -shared -o crypt.so -fPIC crypt.c  -I/usr/include/luajit-2.0 -lcrypto -lluajit-5.1

install:
	cp crypt.so lua
