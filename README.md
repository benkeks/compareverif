# CryptoVerif Examples

This repository contains example protocols for [CryptoVerif](https://cryptoverif.inria.fr/), a cryptographic protocol verification tool.

## About CryptoVerif

CryptoVerif is an automatic protocol verifier that analyzes cryptographic protocols in the computational model. It can prove security properties of protocols such as secrecy and authentication under computational assumptions.

## Prerequisites

To run these examples, you need to install CryptoVerif:

1. Download CryptoVerif from [https://cryptoverif.inria.fr/](https://cryptoverif.inria.fr/)
2. Follow the installation instructions for your platform
3. Make sure `cryptoverif` is in your PATH

## Examples

This repository contains the following examples:

### 1. Symmetric Encryption (`examples/symmetric_enc.cv`)

A simple example demonstrating symmetric encryption with:
- Key generation
- Encryption and decryption operations
- Security proof for message secrecy

### 2. Diffie-Hellman Key Exchange (`examples/diffie_hellman.cv`)

An implementation of the Diffie-Hellman key exchange protocol with:
- Key pair generation
- Shared secret computation
- Security proof under the DDH assumption

## Running the Examples

You can verify all examples using the provided Makefile:

```bash
# Verify all examples
make all

# Verify a specific example
make symmetric_enc
make diffie_hellman

# Clean generated files
make clean
```

Or run CryptoVerif directly on individual files:

```bash
cryptoverif examples/symmetric_enc.cv
cryptoverif examples/diffie_hellman.cv
```

## Project Structure

```
.
├── README.md           # This file
├── Makefile           # Build automation
└── examples/          # Example protocol files
    ├── symmetric_enc.cv
    └── diffie_hellman.cv
```

## Learning Resources

- [CryptoVerif Manual](https://cryptoverif.inria.fr/cryptoverif-manual.pdf)
- [CryptoVerif Tutorial](https://cryptoverif.inria.fr/)
- Example protocols in the CryptoVerif distribution

## Contributing

Feel free to add more examples or improve existing ones. Submit a pull request with your changes.

## License

These examples are provided as educational material and can be freely used and modified.