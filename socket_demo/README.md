# Socket-based Hybrid Key Exchange Demo

This package provides socket-based client-server implementations of the hybrid post-quantum key exchange, enabling automated load testing.

## Architecture

- **server.c**: TCP server that handles multiple concurrent client connections
- **client.c**: TCP client that connects to server, performs key exchange, and sends encrypted messages

## Protocol Flow

1. Client connects to server
2. Server sends its ECDH + Kyber public keys
3. Client generates its keys, performs key exchange, encrypts message
4. Client sends encrypted data to server
5. Server decrypts and responds with success/failure

## Building

```bash
make          # Build both server and client
make server   # Build only server
make client   # Build only client
make clean    # Clean build artifacts
```

## Running

### Basic Test
```bash
# Terminal 1: Start server
make run-server

# Terminal 2: Run client
make run-client
```

### Load Testing
```bash
# Terminal 1: Start server (leave running)
./server

# Terminal 2: Run load test with 10 concurrent clients
make load-test

# Or run custom load test parameters:
# ./load_test.sh <server_ip> <server_port> <num_clients> <batch_size> <client_debug>
./load_test.sh 127.0.0.1 8080 120 40 0
```

### Custom Server IP
```bash
# Connect to different server
./client 192.168.1.100
```

## Features for Load Testing

- **Concurrent connections**: Server handles multiple simultaneous clients
- **Fresh keys per connection**: ECDH keys are regenerated for each connection (perfect forward secrecy)
- **Static Kyber keys**: Server uses pre-generated Kyber keypair for efficiency
- **Automated protocol**: No manual key exchange or data entry required
- **Error handling**: Robust error handling and connection management

## Performance Notes

- Server can handle many concurrent connections (tested with 100+)
- Each connection performs full hybrid key exchange
- ECDH provides forward secrecy, Kyber provides post-quantum security
- Message encryption uses XSalsa20-Poly1305 via libsodium

## Dependencies

- libsodium (for ECDH and symmetric encryption)
- POSIX sockets (Linux/Unix systems)
- Kyber reference implementation

## Comparison with Manual Demo

| Feature | Manual Demo (`../demo/`) | Socket Demo |
|---------|------------------------|-------------|
| Interface | Manual copy-paste | Automated TCP |
| Concurrency | Single connection | Multiple concurrent |
| Load testing | Not supported | Built-in support |
| Keys | Static Kyber | Static Kyber + fresh ECDH |
| Use case | Learning/debugging | Performance testing |