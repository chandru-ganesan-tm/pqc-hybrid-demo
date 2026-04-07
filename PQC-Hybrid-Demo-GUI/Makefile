# ──────────────────────────────────────────────────────────────
# PQC Hybrid Key Exchange — Build
#
# server  → x86_64 (runs on this host)
# client  → aarch64 (cross-compiled, deployed to S4SK)
#
# Host IP:  192.168.0.100  (server)
# S4SK IP:  192.168.0.5    (client)
# ──────────────────────────────────────────────────────────────

HOST_CC  = gcc
BOARD_CC = aarch64-linux-gnu-gcc

CFLAGS   = -O2 -Wall -Isrc/server/kyber/ref -Isrc/server -DKYBER_K=3
HOST_LDFLAGS  = -lsodium
BOARD_LDFLAGS = -static -lsodium -L/usr/local/aarch64-libsodium/lib

KYBER_SRC = src/server/kyber/ref/kem.c       \
            src/server/kyber/ref/indcpa.c    \
            src/server/kyber/ref/poly.c      \
            src/server/kyber/ref/polyvec.c   \
            src/server/kyber/ref/cbd.c       \
            src/server/kyber/ref/fips202.c   \
            src/server/kyber/ref/verify.c    \
            src/server/kyber/ref/symmetric-shake.c \
            src/server/kyber/ref/reduce.c    \
            src/server/kyber/ref/ntt.c

.PHONY: all clean

all: server shared/bin/client local/client
	@echo ""
	@echo "Built:"
	@file server
	@file shared/bin/client
	@file local/client

server: src/server/server.c $(KYBER_SRC)
	$(HOST_CC) $(CFLAGS) $< $(KYBER_SRC) $(HOST_LDFLAGS) -o $@

shared/bin/client: shared/src/client.c $(KYBER_SRC) | shared/bin
	$(BOARD_CC) $(CFLAGS) $< $(KYBER_SRC) $(BOARD_LDFLAGS) -o $@

local/client: src/server/client.c $(KYBER_SRC) | local
	$(HOST_CC) $(CFLAGS) $< $(KYBER_SRC) $(HOST_LDFLAGS) -o $@

shared/bin:
	mkdir -p shared/bin

local:
	mkdir -p local

clean:
	rm -f server shared/bin/client local/client
