# Compiler and flags
CC      = gcc
# CFLAGS  = -O3 -Wall -Ikyber/ref
CFLAGS = -g -O0 -Wall -Ikyber/ref
LDFLAGS = -lsodium

# Define Kyber variant (2=Kyber512, 3=Kyber768, 4=Kyber1024)
KYBER_K ?= 3

# Add KYBER_K definition to compiler flags
CFLAGS += -DKYBER_K=$(KYBER_K)

# Kyber reference implementation sources
KYBER_SRC = \
    kyber/ref/kem.c \
    kyber/ref/indcpa.c \
    kyber/ref/poly.c \
    kyber/ref/ntt.c \
    kyber/ref/reduce.c \
    kyber/ref/symmetric-shake.c \
    kyber/ref/fips202.c \
    kyber/ref/verify.c \
    kyber/ref/polyvec.c \
     kyber/ref/cbd.c 

# Default target
all: hybrid_demo

# Build the hybrid demo
hybrid_demo: hybrid_demo.c $(KYBER_SRC)
	$(CC) $(CFLAGS) hybrid_demo.c $(KYBER_SRC) $(LDFLAGS) -o hybrid_demo

# Clean build artifacts
clean:
	rm -f hybrid_demo *.o