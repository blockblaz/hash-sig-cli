# Hash-Sig CLI

A command-line interface for the [leanSig](https://github.com/leanEthereum/leanSig) library - a prototype implementation of hash-based signatures for post-quantum cryptography.

## Overview

This CLI tool provides a user-friendly interface to work with hash-based signatures, keeping the main `leanSig` repository focused on cryptography while providing practical tooling in a separate codebase.

## Prerequisites

- Rust >= 1.87
- Internet connection (to fetch the `leanSig` dependency from GitHub)

## Installation

```bash
cargo build --release
```

## Usage

Generate validator key pairs for hash-based signatures:

```bash
cargo run --release --bin hashsig -- generate \
  --num-validators 5 \
  --log-num-active-epochs 18 \
  --output-dir ./generated_keys
```

**Parameters:**
- `--num-validators`: Number of validator key pairs to generate
- `--log-num-active-epochs`: Log2 of the number of active epochs (e.g., 18 for 2^18 = 262,144 active epochs)
- `--output-dir`: Directory where keys will be saved
- `--create-manifest`: Create a manifest file (optional, defaults to `true`)

**Output:**
The tool creates a directory with key pairs exported as **SSZ-encoded binary files**:
```
generated_keys/
├── validator-keys-manifest.yaml  # Manifest file (if --create-manifest is true)
├── validator_0_pk.ssz            # Public key for validator 0 (SSZ bytes)
├── validator_0_sk.ssz            # Secret key for validator 0 (SSZ bytes)
├── validator_1_pk.ssz            # Public key for validator 1 (SSZ bytes)
├── validator_1_sk.ssz            # Secret key for validator 1 (SSZ bytes)
└── ...
```

The `.ssz` files contain the **canonical SSZ serialization** (`to_bytes()`) of the underlying key types from `leanSig`, written directly as raw bytes (not JSON or hex).

## Current Implementation

Currently uses the `SIGTopLevelTargetSumLifetime32Dim64Base8` scheme:
- **Hash Function**: Poseidon2 (ZK-friendly)
- **Encoding**: Target Sum 
- **Lifetime**: 2^32 epochs (4,294,967,296)


## References

- [LeanSig Repository](https://github.com/leanEthereum/leanSig)
- [Research Paper](https://eprint.iacr.org/2025/055.pdf)

## License

Apache Version 2.0 (same as leanSig)

## Contributing

This is a separate codebase from the main `leanSig` library to keep the cryptography-focused repository minimal and focused. Feel free to contribute CLI enhancements here.
