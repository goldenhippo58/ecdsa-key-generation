# ECDSA Key Generation

This project provides a C implementation for generating compressed public keys from private keys using the ECDSA (Elliptic Curve Digital Signature Algorithm) with the secp256k1 curve.

## Features

- Generate compressed public keys from private keys
- Uses OpenSSL library for cryptographic operations
- Supports secp256k1 curve

## Prerequisites

Before you begin, ensure you have met the following requirements:

- GCC compiler
- OpenSSL development libraries

On Ubuntu or Debian-based systems, you can install OpenSSL development libraries with:

```
sudo apt-get install libssl-dev
```

## Compilation

To compile the project, use the following command:

```
gcc -o ecdsa_keygen ecdsa_keygen.c -lssl -lcrypto
```

## Usage

After compilation, you can run the program with:

```
./ecdsa_keygen
```

The program will generate a compressed public key from a hardcoded private key and print it to the console.

## File Structure

- `ecdsa_keygen.c`: Main source file containing the implementation
- `ecdsa_keygen.h`: Header file with function declarations

## Function Documentation

### `int generate_compressed_public_key(const uint8_t *private_key, uint8_t *compressed_public_key)`

Generates a compressed public key from a given private key.

Parameters:
- `private_key`: Pointer to a 32-byte array containing the private key
- `compressed_public_key`: Pointer to a 33-byte array where the compressed public key will be stored

Returns:
- The length of the compressed public key on success
- -1 on failure

## License

This project is open source and available under the [MIT License](LICENSE).

## Contributing

Contributions to this project are welcome. Please fork the repository and submit a pull request with your changes.
