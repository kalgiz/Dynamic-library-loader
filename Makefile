

libloader.so: loader.c loader.h
	gcc -m32 -shared -fPIC -o libloader.so loader.c -nostdlib -Wl,--hash-style=sysv
	
clean:
	rm -f libloader.so