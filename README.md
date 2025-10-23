# CryptoVerif Examples

[![Test CryptoVerif Examples](https://github.com/benkeks/verif/actions/workflows/test-examples.yml/badge.svg)](https://github.com/benkeks/verif/actions/workflows/test-examples.yml)

This repository contains example protocols for [CryptoVerif](https://cryptoverif.inria.fr/), a cryptographic protocol verification tool.

## About CryptoVerif

CryptoVerif is an automatic protocol verifier that analyzes cryptographic protocols in the computational model. It can prove security properties of protocols such as secrecy and authentication under computational assumptions.

**Note:** These examples are written for CryptoVerif version 2.11 and later.

## Getting Started

New to CryptoVerif? Check out our [Quick Start Guide](QUICKSTART.md) for step-by-step installation and usage instructions.

## Prerequisites

To run these examples, you need to install CryptoVerif:

1. Download CryptoVerif from [https://cryptoverif.inria.fr/](https://cryptoverif.inria.fr/)
2. Follow the installation instructions for your platform
3. Make sure `cryptoverif` is in your PATH

For detailed installation help, see [QUICKSTART.md](QUICKSTART.md).

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

### 3. Authenticated Encryption (`examples/authenticated_enc.cv`)

A more advanced example showing authenticated encryption (encrypt-then-MAC) with:
- Combined confidentiality and authenticity
- MAC verification before decryption
- Security proofs under IND-CPA and SUF-CMA assumptions

## Running the Examples

You can verify all examples using the provided Makefile:

```bash
# Verify all examples
make all

# Verify a specific example
make symmetric_enc
make diffie_hellman
make authenticated_enc

# Clean generated files
make clean
```

Or run CryptoVerif directly on individual files:

```bash
cryptoverif examples/symmetric_enc.cv
cryptoverif examples/diffie_hellman.cv
cryptoverif examples/authenticated_enc.cv
```

## Project Structure

```
.
├── README.md           # This file
├── Makefile           # Build automation
└── examples/          # Example protocol files
    ├── symmetric_enc.cv
    ├── diffie_hellman.cv
    └── authenticated_enc.cv
```

## Continuous Integration

This repository includes GitHub Actions workflows that automatically test all examples with CryptoVerif 2.11. The CI ensures that:
- All example files have correct syntax
- CryptoVerif can successfully analyze each protocol
- The Makefile targets work as expected

You can view the test results in the [Actions tab](https://github.com/benkeks/verif/actions).

## Learning Resources

- [CryptoVerif Manual](https://cryptoverif.inria.fr/cryptoverif-manual.pdf)
- [CryptoVerif Tutorial](https://cryptoverif.inria.fr/)
- Example protocols in the CryptoVerif distribution

## Contributing

We welcome contributions! Whether you want to add new examples, improve documentation, or fix bugs, please see our [Contributing Guide](CONTRIBUTING.md) for details on how to get started.

## License

These examples are provided as educational material and can be freely used and modified.