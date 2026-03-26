CC = gcc
CFLAGS = -O2 -Wall -I.. -I../kyber/ref -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lsodium

# Kyber source files
KYBER_SRC = ../kyber/ref/kem.c ../kyber/ref/indcpa.c ../kyber/ref/poly.c ../kyber/ref/polyvec.c ../kyber/ref/cbd.c ../kyber/ref/fips202.c ../kyber/ref/verify.c ../kyber/ref/symmetric-shake.c ../kyber/ref/reduce.c ../kyber/ref/ntt.c

# Default target
all: server client

# Build server
server: server.c $(KYBER_SRC)
	$(CC) $(CFLAGS) server.c $(KYBER_SRC) $(LDFLAGS) -o server

# Build client
client: client.c $(KYBER_SRC)
	$(CC) $(CFLAGS) client.c $(KYBER_SRC) $(LDFLAGS) -o client

# Build both server and client
both: server client

# Clean build artifacts
clean:
	rm -f server client *.o

# Run server
run-server: server
	./server

# Run client
run-client: client
	./client

# Run load test (requires server to be running)
load-test: client
	@echo "Running load test with 10 concurrent clients..."
	@for i in $$(seq 1 10); do \
		./client & \
	done; \
	wait

.PHONY: all clean run-server run-client load-test