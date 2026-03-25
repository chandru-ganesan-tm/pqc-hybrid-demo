CC = gcc
CFLAGS = -O2 -Wall -I.. -I../kyber/ref -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lsodium

# Kyber source files
KYBER_SRC = ../kyber/ref/kem.c ../kyber/ref/indcpa.c ../kyber/ref/poly.c ../kyber/ref/polyvec.c ../kyber/ref/cbd.c ../kyber/ref/fips202.c ../kyber/ref/verify.c ../kyber/ref/symmetric-shake.c ../kyber/ref/reduce.c ../kyber/ref/ntt.c

# Define Kyber variant (2=Kyber512, 3=Kyber768, 4=Kyber1024)
KYBER_K ?= 3
CFLAGS += -DKYBER_K=$(KYBER_K)

# Default target
all: sender receiver

# Build sender
sender: sender.c $(KYBER_SRC)
	$(CC) $(CFLAGS) sender.c $(KYBER_SRC) $(LDFLAGS) -o sender

# Build receiver  
receiver: receiver.c $(KYBER_SRC)
	$(CC) $(CFLAGS) receiver.c $(KYBER_SRC) $(LDFLAGS) -o receiver

# Build both sender and receiver
both: sender receiver

# Clean build artifacts
clean:
	rm -f sender receiver *.o