CC = gcc
CFLAGS = -Wall -O2
OPENSSL_LIBS = -lcrypto

KYBER_DIR = kyber/ref
KYBER_SRCS = $(KYBER_DIR)/kem.c $(KYBER_DIR)/indcpa.c $(KYBER_DIR)/ntt.c $(KYBER_DIR)/poly.c $(KYBER_DIR)/polyvec.c $(KYBER_DIR)/reduce.c

all: hybrid_example

hybrid_example: hybrid_example.c $(KYBER_SRCS)
	$(CC) $(CFLAGS) -o $@ hybrid_example.c $(KYBER_SRCS) $(OPENSSL_LIBS)

clean:
	rm -f hybrid_example