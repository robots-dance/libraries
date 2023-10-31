MD5=md5.o
CALCSIN=calcsin
MD5SUM=md5sum

CFLAGS+=-std=c99

BUILD_PROGRAM=$(CC) $(CFLAGS) -o $@ $^

all: $(CALCSIN) $(MD5SUM)

$(CALCSIN): calcsin.c
	$(BUILD_PROGRAM) -lm

$(MD5SUM): main.c $(MD5)
	$(BUILD_PROGRAM)	

clean:
	rm -f $(CALCSIN)
	rm -f $(MD5)
	rm -f $(MD5SUM)

