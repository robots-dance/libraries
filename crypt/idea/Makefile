BUILD_PROGRAM=$(CC) -std=c99 -o $@ $^
BUILD_MODULE=$(CC) -std=c99 -c $<

encryptor: main.c idea.o diff.o iutils.o
	$(BUILD_PROGRAM)

test: test.c idea.o diff.o
	$(BUILD_PROGRAM)

diff.o: diff.c diff.h
	$(BUILD_MODULE)

idea.o: idea.c idea.h diff.o
	$(BUILD_MODULE)

iutils.o: iutils.c
	$(BUILD_MODULE)

clean:
	rm -f diff.o
	rm -f idea.o
	rm -f iutils.o
	rm -f encryptor
	rm -f test
