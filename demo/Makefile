CC = gcc
CFLAGS = -O2 -Wall -I./kyber/ref -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lsodium

# Adjust KYBER_SRC to point to your Kyber source files
KYBER_SRC = kyber/ref/api.c kyber/ref/kem.c kyber/ref/fips202.c kyber/ref/indcpa.c kyber/ref/cbd.c kyber/ref/poly.c kyber/ref/polyvec.c

OBJ = hybrid_demo.o $(KYBER_SRC:.c=.o)

all: hybrid_demo

%.o: %.c
\t$(CC) $(CFLAGS) -c $< -o $@

hybrid_demo: $(OBJ)
\t$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
\trm -f hybrid_demo $(OBJ)