.PHONY: all clean

ENCRYPTOR=encryptor
ENCRYPTOR_ssl=encryptor_ssl
GENBYTES=genbytes
CALC_MIX=calc-mix
CALC_SUBBYTES=calc-subbytes
TEST_AES=test-aes
AES=aes.o
UTILS=utils.o

OBJS=$(AES) $(UTILS)

CC=gcc
CFLAGS+=-O3 -Wno-deprecated-declarations -std=c99

%.o: %.c
	$(CC) $(CFLAGS) -c $<

BUILD_PROGRAM=$(CC) $(CFLAGS) -o $@ $^

all: $(ENCRYPTOR) $(ENCRYPTOR_ssl) $(GENBYTES) \
	$(CALC_SUBBYTES) $(CALC_MIX) $(TEST_AES)

$(ENCRYPTOR): main.c $(OBJS) 
	$(BUILD_PROGRAM)

$(ENCRYPTOR_ssl): main.c $(OBJS) 
	$(BUILD_PROGRAM) -DUSE_OPENSSL=1 -lcrypto

$(GENBYTES): genbytes.c
	$(BUILD_PROGRAM) -lcrypto

$(CALC_MIX): calc-mix.c $(UTILS)
	$(BUILD_PROGRAM)

$(CALC_SUBBYTES): calc-subbytes.c $(UTILS)
	$(BUILD_PROGRAM)

$(TEST_AES): test-aes.c $(OBJS) 
	$(BUILD_PROGRAM)

clean:
	rm -f $(ENCRYPTOR)
	rm -f $(ENCRYPTOR_ssl)
	rm -f $(GENBYTES)
	rm -f $(CALC_MIX)
	rm -f $(CALC_SUBBYTES)
	rm -f $(TEST_AES)
	rm -f *.o
