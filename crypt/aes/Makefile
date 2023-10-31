encryptor: main.c crypt.o
	gcc -O3 -std=c99 -o $@ $^

crypt.o: crypt.c crypt.h
	gcc -O3 -std=c99 -c $<

clean:
	rm -f crypt.o
	rm -f encryptor
