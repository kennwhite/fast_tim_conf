all:
	gcc -o crypt.o crypt.c -L/usr/include -luajit-2.0

install:
	mv lua /var/www/lua
	mv crypt.o /var/www
