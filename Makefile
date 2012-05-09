build:
	gcc -fPIC -c md5crypt.c
	gcc -shared -Wl -o libmd5crypt.so md5crypt.o -lcrypto
clean:
	rm *.o
	rm *.so
