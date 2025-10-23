# Makefile for CryptoVerif Examples

# CryptoVerif executable
CRYPTOVERIF = cryptoverif

# Example files
EXAMPLES = examples/symmetric_enc.cv examples/diffie_hellman.cv examples/authenticated_enc.cv

# Output directory for results
OUT_DIR = output

.PHONY: all clean symmetric_enc diffie_hellman authenticated_enc help

# Default target
all: $(EXAMPLES)
	@echo "Verifying all examples..."
	@mkdir -p $(OUT_DIR)
	@for example in $(EXAMPLES); do \
		echo ""; \
		echo "=== Verifying $$example ==="; \
		$(CRYPTOVERIF) -o $(OUT_DIR)/$$(basename $$example .cv).out $$example || true; \
	done
	@echo ""
	@echo "Verification complete. Results saved in $(OUT_DIR)/"

# Individual targets
symmetric_enc:
	@echo "Verifying symmetric encryption example..."
	@mkdir -p $(OUT_DIR)
	$(CRYPTOVERIF) -o $(OUT_DIR)/symmetric_enc.out examples/symmetric_enc.cv

diffie_hellman:
	@echo "Verifying Diffie-Hellman key exchange example..."
	@mkdir -p $(OUT_DIR)
	$(CRYPTOVERIF) -o $(OUT_DIR)/diffie_hellman.out examples/diffie_hellman.cv

authenticated_enc:
	@echo "Verifying authenticated encryption example..."
	@mkdir -p $(OUT_DIR)
	$(CRYPTOVERIF) -o $(OUT_DIR)/authenticated_enc.out examples/authenticated_enc.cv

# Clean generated files
clean:
	@echo "Cleaning output files..."
	rm -rf $(OUT_DIR)
	@echo "Clean complete."

# Help target
help:
	@echo "CryptoVerif Examples - Available targets:"
	@echo ""
	@echo "  make all              - Verify all examples"
	@echo "  make symmetric_enc    - Verify symmetric encryption example"
	@echo "  make diffie_hellman   - Verify Diffie-Hellman example"
	@echo "  make authenticated_enc - Verify authenticated encryption example"
	@echo "  make clean            - Remove generated files"
	@echo "  make help             - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - CryptoVerif must be installed and in PATH"
	@echo "  - Download from: https://cryptoverif.inria.fr/"
