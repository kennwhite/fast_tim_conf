all:
	gcc -o crypt.o crypt.c -L/usr/local/lib -lluajit-5.1

install:
	mv lua /var/www/lua
	mv crypt.o /var/www
