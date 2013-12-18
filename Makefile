all:
	gcc -o crypt.so crypt.c -I/usr/include/luajit-2.0 -lcrypto -lluajit-5.1

install:
	cp -r lua /var/www
	cp crypt.so /var/www/lua
