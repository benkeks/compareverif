# Contributing to CryptoVerif Examples

Thank you for your interest in contributing! This document provides guidelines for contributing to this repository.

## How to Contribute

### Adding New Examples

We welcome new CryptoVerif protocol examples! Here's how to add one:

1. **Fork the repository** and create a new branch for your example

2. **Create your example file** in the `examples/` directory:
   ```bash
   examples/your_protocol_name.cv
   ```

3. **Follow the existing style**:
   - Add a descriptive comment block at the top explaining the protocol
   - Use clear variable and function names
   - Include comments for complex sections
   - Add appropriate security queries

4. **Update the README.md**:
   - Add your example to the "Examples" section
   - Include a brief description
   - Add the command to run it

5. **Update the Makefile**:
   - Add your example to the `EXAMPLES` variable
   - Add a `.PHONY` target for your example
   - Add a make target to run it individually
   - Update the help text

6. **Test your example**:
   ```bash
   cryptoverif examples/your_protocol_name.cv
   ```
   Make sure it runs without errors.

7. **Submit a pull request** with:
   - Clear description of the protocol
   - Why it's a useful example
   - Any relevant papers or references

### Example Topics We'd Love to See

- Digital signatures schemes
- Key derivation functions
- TLS handshake variants
- SSH authentication
- Secure messaging protocols
- Password-based authentication
- Zero-knowledge proofs
- Multi-party protocols

### Improving Existing Examples

Found a bug or improvement? Great! Here's what to do:

1. Open an issue describing the problem or improvement
2. Fork the repository and make your changes
3. Test that the example still verifies correctly
4. Submit a pull request referencing the issue

### Documentation Improvements

Documentation improvements are always welcome:

- Fix typos or unclear explanations
- Add more detailed comments to protocols
- Improve installation instructions
- Add troubleshooting tips
- Create tutorials or guides

## Code Style Guidelines

### CryptoVerif Files (.cv)

```ocaml
(* Use descriptive header comments *)
(* explaining what the protocol does *)

(* Group related declarations together *)
type key [large, fixed].
type message [large, fixed].

(* Comment complex functions *)
fun enc(message, key): ciphertext.

(* Add whitespace for readability *)
process
  new k: key;
  out(c, enc(msg, k))
```

### Makefile

- Use tab indentation (required by make)
- Add `.PHONY` declarations for non-file targets
- Include descriptive echo messages
- Handle errors gracefully with `|| true` where appropriate

### Documentation (Markdown)

- Use clear, concise language
- Include code examples
- Use proper markdown formatting
- Link to relevant resources

## Testing Your Contribution

Before submitting, ensure:

1. ✅ Your example runs without errors:
   ```bash
   cryptoverif examples/your_example.cv
   ```

2. ✅ The Makefile works:
   ```bash
   make clean
   make your_example
   make all
   ```

3. ✅ Documentation is updated and accurate

4. ✅ No syntax errors or typos

## Questions?

If you have questions about contributing, feel free to:

- Open an issue for discussion
- Check the [CryptoVerif manual](https://cryptoverif.inria.fr/cryptoverif-manual.pdf)
- Look at existing examples for guidance

## License

By contributing, you agree that your contributions will be provided under the same terms as this project (see LICENSE file).

Thank you for helping make this resource better for everyone! 🎉
