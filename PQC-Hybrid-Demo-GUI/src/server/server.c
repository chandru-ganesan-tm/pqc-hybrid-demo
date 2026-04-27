/* ══════════════════════════════════════════════════════════════════
 *  PQC Hybrid Key Exchange — Server  (phased, GUI-driven)
 *
 *  Flow per exchange:
 *    1. Generate ECDH keypair + Kyber keypair  → report to GUI
 *    2. WAIT for client to connect (port 8080)
 *    3. Send public keys to client
 *    4. Receive client bundle (ECDH pk, Kyber ct, nonce, ciphertext)
 *       → report received data to GUI
 *    5. WAIT for GUI to send "PROCESS\n" on the GUI socket
 *    6. ECDH derive + Kyber decap + hybrid KDF + decrypt → report
 *    7. Send SUCCESS to client, close client socket
 *    8. Loop back to step 1
 *
 *  Flags:
 *    --debug / -d          Verbose human-readable logging to stderr
 *    --gui PORT / -g PORT  Open report port; GUI connects once,
 *                          receives JSON events + sends commands
 * ══════════════════════════════════════════════════════════════════ */


/* ──────────────────────────────────────────────────────────────────
 *  SECTION: Includes & Defines
 * ────────────────────────────────────────────────────────────────── */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sodium.h>

#include "./kyber/ref/api.h"
#include "./kyber/ref/kem.h"

#define HYBRID_KEY_BYTES  32
#define PORT              8080

static int pqc_port = PORT;
#define JSON_BUF          8192
#define HEX_SMALL         (64 + 1)
#define HEX_LARGE         (CRYPTO_PUBLICKEYBYTES * 2 + 1)
#define HEX_CT            (CRYPTO_CIPHERTEXTBYTES * 2 + 1)
#define CMD_BUF           256

#define KEX_FLAG_ECDH_PK  0x01
#define KEX_FLAG_KYBER_CT 0x02


/* ──────────────────────────────────────────────────────────────────
 *  SECTION: Globals & Debug Logging
 * ────────────────────────────────────────────────────────────────── */

static int debug   = 0;
static int gui_fd  = -1;
static int gui_port = 0;

#define LOG(fmt, ...) \
    do { if (debug) fprintf(stderr, "[server] " fmt, ##__VA_ARGS__); } while (0)


/* ──────────────────────────────────────────────────────────────────
 *  SECTION: Utility — Timing & Socket Helpers
 * ────────────────────────────────────────────────────────────────── */

static double get_time_diff(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
}

static ssize_t send_all(int fd, const void *buf, size_t len) {
    size_t total = 0;
    const unsigned char *p = buf;
    while (total < len) {
        ssize_t s = send(fd, p + total, len - total, 0);
        if (s <= 0) return s;
        total += s;
    }
    return total;
}

static ssize_t recv_all(int fd, void *buf, size_t len) {
    size_t total = 0;
    unsigned char *p = buf;
    while (total < len) {
        ssize_t r = recv(fd, p + total, len - total, 0);
        if (r <= 0) return r;
        total += r;
    }
    return total;
}


/* ──────────────────────────────────────────────────────────────────
 *  SECTION: JSON / GUI Reporting + Command Receive
 * ────────────────────────────────────────────────────────────────── */

static void to_hex(char *out, const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", data[i]);
    out[len * 2] = '\0';
}

static void gui_event(const char *fmt, ...) {
    if (gui_fd < 0) return;

    char buf[JSON_BUF];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0 || n >= (int)sizeof(buf)) return;

    if (write(gui_fd, buf, n) < 0 || write(gui_fd, "\n", 1) < 0) {
        gui_fd = -1;
    }
}

/* Return codes for gui_wait_command / accept_or_reset */
#define GUI_CMD_OK    0   /* expected command received */
#define GUI_CMD_RESET 1   /* RESET received — restart exchange */
#define GUI_CMD_ERR  -1   /* connection lost */

/* Block until the GUI sends the expected command or "RESET".
 * Returns GUI_CMD_OK, GUI_CMD_RESET, or GUI_CMD_ERR. */
static int gui_wait_command(const char *expected) {
    if (gui_fd < 0) return GUI_CMD_OK;   /* no GUI → don't block */

    LOG("Waiting for GUI command: %s\n", expected);

    char buf[CMD_BUF];
    size_t pos = 0;

    while (1) {
        char c;
        ssize_t r = read(gui_fd, &c, 1);
        if (r <= 0) { gui_fd = -1; return GUI_CMD_ERR; }
        if (c == '\n') {
            buf[pos] = '\0';
            LOG("Received command: %s\n", buf);
            if (strncmp(buf, expected, strlen(expected)) == 0) return GUI_CMD_OK;
            if (strncmp(buf, "RESET", 5)          == 0) return GUI_CMD_RESET;
            pos = 0;   /* unknown command, keep reading */
        } else if (pos < sizeof(buf) - 1) {
            buf[pos++] = c;
        }
    }
}

/* Wait for a client connection while also monitoring the GUI fd for a RESET
 * command.  Returns: connected client fd (>= 0), GUI_CMD_RESET (-1), or
 * GUI_CMD_ERR (-2) on hard error. */
static int accept_or_reset(int srv_fd, struct sockaddr_in *addr, int *addrlen) {
    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(srv_fd, &rfds);
        if (gui_fd >= 0) FD_SET(gui_fd, &rfds);
        int nfds = srv_fd + 1;
        if (gui_fd >= 0 && gui_fd + 1 > nfds) nfds = gui_fd + 1;

        if (select(nfds, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            return -2;
        }

        /* GUI command takes priority — check before accept */
        if (gui_fd >= 0 && FD_ISSET(gui_fd, &rfds)) {
            char buf[CMD_BUF];
            size_t pos = 0;
            while (pos < sizeof(buf) - 1) {
                char c;
                ssize_t r = read(gui_fd, &c, 1);
                if (r <= 0) { gui_fd = -1; break; }
                if (c == '\n') { buf[pos] = '\0'; break; }
                buf[pos++] = c;
            }
            buf[pos] = '\0';
            LOG("accept_or_reset: received command: %s\n", buf);
            if (strncmp(buf, "RESET", 5) == 0) return GUI_CMD_RESET;
            /* Unknown command while waiting for client — ignore */
        }

        if (FD_ISSET(srv_fd, &rfds)) {
            int cs = accept(srv_fd, (struct sockaddr *)addr, (socklen_t *)addrlen);
            return cs;
        }
    }
}

static void print_keysizes()
{
    const char *kyber_variant = "Kyber768";

    LOG("Key sizes:\n");

    if(KYBER_K == 2) {
        kyber_variant = "Kyber512";
        LOG("Kyber variant: Kyber512\n");
    } else if(KYBER_K == 3) {
        kyber_variant = "Kyber768";
        LOG("Kyber variant: Kyber768\n");
    } else if(KYBER_K == 4) {
        kyber_variant = "Kyber1024";
        LOG("Kyber variant: Kyber1024\n");
    }

    LOG("CRYPTO_PUBLICKEYBYTES (Kyber pubkey) = %d\n", CRYPTO_PUBLICKEYBYTES);
    LOG("crypto_kx_PUBLICKEYBYTES (ECDH pubkey) = %d\n", crypto_kx_PUBLICKEYBYTES);
    LOG("CRYPTO_SECRETKEYBYTES (kyber privkey) = %d\n", CRYPTO_SECRETKEYBYTES);
    LOG("crypto_kx_SECRETKEYBYTES (ecdhe privkey) = %d\n", crypto_kx_SECRETKEYBYTES);
    LOG("CRYPTO_BYTES (kyber shared secret) = %d\n", CRYPTO_BYTES);
    LOG("crypto_kx_SESSIONKEYBYTES (ecdhe shared secret) = %d\n", crypto_kx_SESSIONKEYBYTES);
    LOG("CRYPTO_CIPHERTEXTBYTES (kyber ciphertext) = %d\n", CRYPTO_CIPHERTEXTBYTES);
    LOG("HYBRID_KEY_BYTES (final symmetric key) = %d\n", HYBRID_KEY_BYTES);
    LOG("NONCEBYTES = %d\n", crypto_secretbox_NONCEBYTES);

    gui_event("{\"event\":\"keysizes\",\"source\":\"server\","
              "\"kyber_variant\":\"%s\","
              "\"kyber_pk\":%d,\"ecdh_pk\":%d,"
              "\"kyber_sk\":%d,\"ecdh_sk\":%d,"
              "\"kyber_ss\":%d,\"ecdh_ss\":%d,"
              "\"kyber_ct\":%d,\"hybrid_key\":%d,\"nonce\":%d}",
              kyber_variant,
              CRYPTO_PUBLICKEYBYTES,
              crypto_kx_PUBLICKEYBYTES,
              CRYPTO_SECRETKEYBYTES,
              crypto_kx_SECRETKEYBYTES,
              CRYPTO_BYTES,
              crypto_kx_SESSIONKEYBYTES,
              CRYPTO_CIPHERTEXTBYTES,
              HYBRID_KEY_BYTES,
              crypto_secretbox_NONCEBYTES);
}


/* ══════════════════════════════════════════════════════════════════
 *  SECTION: main()
 * ══════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {

    /* ── Argument Parsing ──────────────────────────────────────── */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            debug = 1;
        } else if ((strcmp(argv[i], "--gui") == 0 || strcmp(argv[i], "-g") == 0)
                   && i + 1 < argc) {
            gui_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--gui-fd") == 0 && i + 1 < argc) {
            gui_fd = atoi(argv[++i]);   /* pre-connected fd from parent */
        } else if ((strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-p") == 0)
                   && i + 1 < argc) {
            pqc_port = atoi(argv[++i]);
        }
    }

    signal(SIGPIPE, SIG_IGN);

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    /* ── PQC Listener Socket (port 8080) ───────────────────────── */

    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket"); return 1;
    }
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(pqc_port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("listen"); return 1;
    }

    LOG("Listening on port %d\n", pqc_port);


    /* ── GUI Reporter Socket (--gui PORT or --gui-fd FD) ─────────── */

    if (gui_fd >= 0) {
        /* Pre-connected fd from parent (socketpair / pipe) */
        LOG("Using pre-connected GUI fd %d\n", gui_fd);
        gui_event("{\"event\":\"gui_connected\"}");
    } else if (gui_port > 0) {
        int gl = socket(AF_INET, SOCK_STREAM, 0);
        if (gl < 0) { perror("gui socket"); return 1; }
        setsockopt(gl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in ga = {0};
        ga.sin_family      = AF_INET;
        ga.sin_addr.s_addr = INADDR_ANY;
        ga.sin_port        = htons(gui_port);

        if (bind(gl, (struct sockaddr *)&ga, sizeof(ga)) < 0) {
            perror("gui bind"); return 1;
        }
        if (listen(gl, 1) < 0) {
            perror("gui listen"); return 1;
        }

        LOG("Waiting for GUI on port %d...\n", gui_port);
        gui_fd = accept(gl, NULL, NULL);
        if (gui_fd < 0) { perror("gui accept"); return 1; }

        int flag = 1;
        setsockopt(gui_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        close(gl);

        LOG("GUI connected (fd %d)\n", gui_fd);
        gui_event("{\"event\":\"gui_connected\"}");
    }

    /* Emit key-size logs/events only after GUI fd is available. */
    print_keysizes();
    gui_event("{\"event\":\"listening\",\"port\":%d}", pqc_port);


    /* ══════════════════════════════════════════════════════════════
     *  SECTION: Main Exchange Loop (phased, GUI-driven)
     * ══════════════════════════════════════════════════════════════ */

    struct timespec ts0, ts1;
    double t;

    while (1) {

        /* ── Phase 1: Generate Keys ────────────────────────────── *
         *  Done BEFORE accept so the GUI can show them while       *
         *  waiting for the client to connect.                      *
         * ────────────────────────────────────────────────────────── */

        unsigned char recv_kx_pk[crypto_kx_PUBLICKEYBYTES];
        unsigned char recv_kx_sk[crypto_kx_SECRETKEYBYTES];

        clock_gettime(CLOCK_MONOTONIC, &ts0);
        if (crypto_kx_keypair(recv_kx_pk, recv_kx_sk) != 0) {
            fprintf(stderr, "ECDH keygen failed\n"); continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        t = get_time_diff(ts0, ts1) * 1000;

        {
            char hex[HEX_SMALL];
            to_hex(hex, recv_kx_pk, crypto_kx_PUBLICKEYBYTES);
            gui_event("{\"event\":\"ecdh_keygen\",\"pk\":\"%s\",\"time_ms\":%.6f}",
                      hex, t);
        }

        unsigned char recv_kyber_pk[CRYPTO_PUBLICKEYBYTES];
        unsigned char recv_kyber_sk[CRYPTO_SECRETKEYBYTES];

        clock_gettime(CLOCK_MONOTONIC, &ts0);
        if (crypto_kem_keypair(recv_kyber_pk, recv_kyber_sk) != 0) {
            fprintf(stderr, "Kyber keygen failed\n"); continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        t = get_time_diff(ts0, ts1) * 1000;

        {
            char hex[HEX_LARGE];
            to_hex(hex, recv_kyber_pk, CRYPTO_PUBLICKEYBYTES);
            gui_event("{\"event\":\"kyber_pk_loaded\",\"pk\":\"%s\",\"time_ms\":%.6f}",
                      hex, t);
        }

        gui_event("{\"event\":\"phase\",\"phase\":\"keys_ready\"}");
        LOG("Keys ready — waiting for client...\n");


        /* ── Phase 2: Accept Client Connection ─────────────────── *
         *  Blocks here until the GUI triggers the board client.    *
         * ────────────────────────────────────────────────────────── */

        int cs = accept_or_reset(server_fd, &address, &addrlen);
        if (cs == GUI_CMD_RESET) {
            LOG("RESET received — regenerating keys.\n");
            gui_event("{\"event\":\"phase\",\"phase\":\"reset\"}");
            continue;
        }
        if (cs < 0) { perror("accept"); continue; }

        const char *cip   = inet_ntoa(address.sin_addr);
        int         cport = ntohs(address.sin_port);
        LOG("Client from %s:%d\n", cip, cport);
        gui_event("{\"event\":\"client_connected\",\"from\":\"%s:%d\"}",
                  cip, cport);


        /* ── Phase 3: Send Public Keys to Client ───────────────── */

        if (send_all(cs, recv_kx_pk, crypto_kx_PUBLICKEYBYTES)
                != crypto_kx_PUBLICKEYBYTES ||
            send_all(cs, recv_kyber_pk, CRYPTO_PUBLICKEYBYTES)
                != CRYPTO_PUBLICKEYBYTES)
        {
            perror("send keys"); close(cs); continue;
        }
        gui_event("{\"event\":\"keys_sent\"}");


        /* ── Phase 4: Receive Client Bundle ────────────────────── */

        unsigned char sender_kx_pk[crypto_kx_PUBLICKEYBYTES];
        unsigned char kyber_ct[CRYPTO_CIPHERTEXTBYTES];
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        unsigned char ciphertext[1024];
        unsigned char proposal_flags = 0;
        uint32_t      ct_len_net;
        size_t        ct_len;

        int has_ecdh = 0;
        int has_kyber = 0;
        const char *kex_mode = "hybrid";

        if (recv_all(cs, &proposal_flags, sizeof(proposal_flags))
                != sizeof(proposal_flags))
        {
            perror("recv proposal flags"); close(cs); continue;
        }

        has_ecdh = (proposal_flags & KEX_FLAG_ECDH_PK) != 0;
        has_kyber = (proposal_flags & KEX_FLAG_KYBER_CT) != 0;

        if (!has_ecdh && !has_kyber) {
            fprintf(stderr, "Invalid client proposal: no key material\n");
            close(cs); continue;
        }

        if (has_ecdh && !has_kyber) {
            kex_mode = "ecdh";
        } else if (!has_ecdh && has_kyber) {
            kex_mode = "pqc";
        }

        memset(sender_kx_pk, 0, sizeof(sender_kx_pk));
        memset(kyber_ct, 0, sizeof(kyber_ct));

        if ((has_ecdh && recv_all(cs, sender_kx_pk, crypto_kx_PUBLICKEYBYTES)
                != crypto_kx_PUBLICKEYBYTES) ||
            (has_kyber && recv_all(cs, kyber_ct, CRYPTO_CIPHERTEXTBYTES)
                != CRYPTO_CIPHERTEXTBYTES) ||
            recv_all(cs, nonce, crypto_secretbox_NONCEBYTES)
                != crypto_secretbox_NONCEBYTES ||
            recv_all(cs, &ct_len_net, sizeof(uint32_t))
                != sizeof(uint32_t))
        {
            perror("recv client data"); close(cs); continue;
        }

        ct_len = ntohl(ct_len_net);
        if (ct_len > sizeof(ciphertext)) {
            fprintf(stderr, "Ciphertext too large\n"); close(cs); continue;
        }
        if (recv_all(cs, ciphertext, ct_len) != (ssize_t)ct_len) {
            perror("recv ciphertext"); close(cs); continue;
        }

        {
            char hex_pk[HEX_SMALL] = "";
            char hex_ct[HEX_CT] = "";
            if (has_ecdh) {
                to_hex(hex_pk, sender_kx_pk, crypto_kx_PUBLICKEYBYTES);
            }
            if (has_kyber) {
                to_hex(hex_ct, kyber_ct, CRYPTO_CIPHERTEXTBYTES);
            }
            gui_event("{\"event\":\"client_data_received\","
                      "\"mode\":\"%s\",\"has_ecdh\":%s,\"has_kyber\":%s,"
                      "\"ecdh_pk\":\"%s\",\"kyber_ct\":\"%s\"}",
                      kex_mode,
                      has_ecdh ? "true" : "false",
                      has_kyber ? "true" : "false",
                      hex_pk, hex_ct);
        }

        gui_event("{\"event\":\"phase\",\"phase\":\"bundle_received\"}");


        /* ── Phase 5: WAIT for GUI "PROCESS" Command ───────────── *
         *  Server has all the data but does NOT process yet.       *
         *  The user drags the "Client Bundle" token in the GUI,    *
         *  which sends "PROCESS\n" to this socket.                 *
         * ────────────────────────────────────────────────────────── */

        {
            int cmd = gui_wait_command("PROCESS");
            if (cmd == GUI_CMD_RESET) {
                LOG("RESET received during PROCESS wait — aborting exchange.\n");
                close(cs);
                gui_event("{\"event\":\"phase\",\"phase\":\"reset\"}");
                continue;
            }
            if (cmd == GUI_CMD_ERR) {
                LOG("GUI disconnected while waiting for PROCESS\n");
            }
        }


        /* ── Phase 6: Process — ECDH + Kyber + Decrypt ─────────── */

        /* 6a. ECDH shared secret */
        unsigned char srv_rx[crypto_kx_SESSIONKEYBYTES] = {0};
        unsigned char srv_tx[crypto_kx_SESSIONKEYBYTES] = {0};
        unsigned char ecdh_shared[crypto_kx_SESSIONKEYBYTES] = {0};

        if (has_ecdh) {
            clock_gettime(CLOCK_MONOTONIC, &ts0);
            if (crypto_kx_server_session_keys(srv_rx, srv_tx,
                    recv_kx_pk, recv_kx_sk, sender_kx_pk) != 0) {
                fprintf(stderr, "ECDH derive failed\n"); close(cs); continue;
            }
            clock_gettime(CLOCK_MONOTONIC, &ts1);
            t = get_time_diff(ts0, ts1) * 1000;

            memcpy(ecdh_shared, srv_rx, crypto_kx_SESSIONKEYBYTES);

            {
                char hex[HEX_SMALL];
                to_hex(hex, ecdh_shared, crypto_kx_SESSIONKEYBYTES);
                gui_event("{\"event\":\"ecdh_derive\","
                          "\"shared\":\"%s\",\"time_ms\":%.6f}", hex, t);
            }
        }

        /* 6b. Kyber decapsulation */
        unsigned char kyber_ss[CRYPTO_BYTES] = {0};

        if (has_kyber) {
            clock_gettime(CLOCK_MONOTONIC, &ts0);
            if (crypto_kem_dec(kyber_ss, kyber_ct, recv_kyber_sk) != 0) {
                fprintf(stderr, "Kyber decap failed\n"); close(cs); continue;
            }
            clock_gettime(CLOCK_MONOTONIC, &ts1);
            t = get_time_diff(ts0, ts1) * 1000;

            {
                char hex[HEX_SMALL];
                to_hex(hex, kyber_ss, CRYPTO_BYTES);
                gui_event("{\"event\":\"kyber_decap\","
                          "\"shared\":\"%s\",\"time_ms\":%.6f}", hex, t);
            }
        }

        /* 6c. Hybrid KDF */
        unsigned char hybrid_key[HYBRID_KEY_BYTES];

        clock_gettime(CLOCK_MONOTONIC, &ts0);
        if (has_ecdh && has_kyber) {
            unsigned char kdf_in[crypto_kx_SESSIONKEYBYTES + CRYPTO_BYTES];
            memcpy(kdf_in, ecdh_shared, crypto_kx_SESSIONKEYBYTES);
            memcpy(kdf_in + crypto_kx_SESSIONKEYBYTES, kyber_ss, CRYPTO_BYTES);
            crypto_hash_sha256(hybrid_key, kdf_in, sizeof(kdf_in));
        } else if (has_ecdh) {
            crypto_hash_sha256(hybrid_key, ecdh_shared, crypto_kx_SESSIONKEYBYTES);
        } else {
            crypto_hash_sha256(hybrid_key, kyber_ss, CRYPTO_BYTES);
        }
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        t = get_time_diff(ts0, ts1) * 1000;

        {
            char hex[HEX_SMALL];
            to_hex(hex, hybrid_key, HYBRID_KEY_BYTES);
            gui_event("{\"event\":\"hybrid_key\","
                      "\"mode\":\"%s\",\"key\":\"%s\",\"time_ms\":%.6f}",
                      kex_mode, hex, t);
        }

        /* 6d. Decrypt */
        unsigned char decrypted[1024];

        clock_gettime(CLOCK_MONOTONIC, &ts0);
        if (crypto_secretbox_open_easy(decrypted, ciphertext,
                ct_len, nonce, hybrid_key) != 0) {
            fprintf(stderr, "Decryption failed\n");
            send(cs, "DECRYPTION_FAILED", 17, 0);
            gui_event("{\"event\":\"error\",\"msg\":\"decryption_failed\"}");
            close(cs); continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        t = get_time_diff(ts0, ts1) * 1000;

        decrypted[ct_len - crypto_secretbox_MACBYTES] = '\0';
        LOG("Decrypted: %s\n", decrypted);

        gui_event("{\"event\":\"decrypt\","
                  "\"plaintext\":\"%s\",\"time_ms\":%.6f}",
                  (char *)decrypted, t);


        /* ── Phase 7: Respond & Loop ───────────────────────────── */

        send_all(cs, "SUCCESS", 7);
        gui_event("{\"event\":\"complete\",\"status\":\"SUCCESS\"}");

        close(cs);
        LOG("Exchange done — waiting for NEXT command.\n\n");

        /* ── Phase 8: Wait for GUI "NEXT" or "RESET" before new round ────── */
        {
            int cmd = gui_wait_command("NEXT");
            if (cmd == GUI_CMD_ERR) {
                LOG("GUI disconnected while waiting for NEXT\n");
            }
            /* GUI_CMD_RESET here just restarts the loop (same as NEXT) */
        }
    }

    close(server_fd);
    if (gui_fd >= 0) close(gui_fd);
    return 0;
}
