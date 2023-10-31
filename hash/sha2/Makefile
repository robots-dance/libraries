.PHONY: all clean

SHA256SUM=sha256sum
SHA512SUM=sha512sum
SHA256=sha256.o
SHA512=sha512.o

CFLAGS+=-std=c99

BUILD_PROGRAM=$(CC) $(CFLAGS) -o $@ $^ 

all: $(SHA256SUM) $(SHA512SUM)

$(SHA256SUM): sha256sum.c $(SHA256)
	$(BUILD_PROGRAM)

$(SHA512SUM): sha512sum.c $(SHA512)
	$(BUILD_PROGRAM)

clean:
	rm -f $(SHA256)
	rm -f $(SHA512)
	rm -f $(SHA256SUM)
	rm -f $(SHA512SUM)
