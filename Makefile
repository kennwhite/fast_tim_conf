all:
	gcc -shared -o crypt.so -fPIC crypt.c  -I/usr/include/luajit-2.0 -lcrypto -lluajit-5.1

install:
	mkdir -p /var/www
	cp static/* /var/www
	cp -r lua /var/www
	cp crypt.so /var/www/lua
