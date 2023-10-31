SHA1=sha1.o
SHA1SUM=sha1sum

CFLAGS+=-std=c99

BUILD_PROGRAM=$(CC) $(CFLAGS) -o $@ $^

all: $(SHA1SUM)

$(SHA1SUM): main.c $(SHA1)
	$(BUILD_PROGRAM)	

clean:
	rm -f $(SHA1)
	rm -f $(SHA1SUM)

