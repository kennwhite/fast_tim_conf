all:
	gcc -o crypt.so crypt.c -I/usr/include/luajit-2.0 -lcrypto -lluajit-5.1

install:
	mv lua /var/www/lua
	mv crypt.so /var/www
