# Quick Start Guide

This guide will help you get started with the CryptoVerif examples in minutes.

## Step 1: Install CryptoVerif

### Linux/macOS

1. Visit [https://cryptoverif.inria.fr/](https://cryptoverif.inria.fr/)
2. Download the latest version
3. Extract the archive:
   ```bash
   tar -xzf cryptoverif2.XX.tar.gz
   cd cryptoverif2.XX
   ```
4. Compile (requires OCaml):
   ```bash
   ./build
   ```
5. Add to PATH or copy binary to `/usr/local/bin`:
   ```bash
   sudo cp cryptoverif /usr/local/bin/
   ```

### Windows

Follow the instructions on the CryptoVerif website for Windows installation.

## Step 2: Clone This Repository

```bash
git clone https://github.com/benkeks/verif.git
cd verif
```

## Step 3: Run Your First Example

### Option A: Using Make

```bash
# View available commands
make help

# Run all examples
make all

# Run a specific example
make symmetric_enc
```

### Option B: Direct Execution

```bash
# Run the symmetric encryption example
cryptoverif examples/symmetric_enc.cv

# Run the Diffie-Hellman example
cryptoverif examples/diffie_hellman.cv

# Run the authenticated encryption example
cryptoverif examples/authenticated_enc.cv
```

## Understanding the Output

When you run CryptoVerif on an example, it will:

1. Parse the protocol specification
2. Apply cryptographic assumptions
3. Perform automated proof search
4. Report whether the security properties hold

Successful verification will show:
```
RESULT Proved queries are:
  query attacker(secretMessage).
```

This means the tool successfully proved that the attacker cannot learn the secret message.

## Next Steps

1. Read the comments in each `.cv` file to understand the protocol
2. Modify the examples to see how changes affect security
3. Try creating your own protocols based on these templates
4. Consult the [CryptoVerif Manual](https://cryptoverif.inria.fr/cryptoverif-manual.pdf) for advanced features

## Troubleshooting

### "cryptoverif: command not found"
- Make sure CryptoVerif is installed and in your PATH
- Try running with full path: `/path/to/cryptoverif examples/symmetric_enc.cv`

### Parse errors
- Check that your `.cv` file syntax matches the examples
- Ensure all parentheses and brackets are balanced
- Verify type declarations come before they are used

### Proof fails
- This might be expected if you modified a protocol in an unsafe way
- Review CryptoVerif output for hints about why the proof failed
- Consult the manual for guidance on fixing the protocol

## Getting Help

- [CryptoVerif Manual](https://cryptoverif.inria.fr/cryptoverif-manual.pdf)
- [CryptoVerif Mailing List](https://cryptoverif.inria.fr/)
- File an issue in this repository
