# Architecture — ternary-zkp

> *Internal design and data flow.*

## Overview

This crate implements ternary {-1, 0, +1} semantics for the `zkp` domain.
It is one of ~280 ternary crates in the SuperInstance fleet, all sharing Z₃ arithmetic
from [ternary-core](https://github.com/SuperInstance/ternary-core).

## Core Types

- **`TernaryField`**
- **`GF3Polynomial`**
- **`PolynomialCommitment`**
- **`PedersenParams`**
- **`ZKProof`**
- **`ZKVerifier`**

## Key Functions

- `modpow()`
- `modinv()`
- `challenge_hash()`
- `new()`
- `add()`
- `sub()`
- `mul()`
- `neg()`

## Ternary Mapping

| Value | Meaning |
|-------|---------|
| +1 | Proof valid |
| 0  | Unknown |
| -1 | Proof invalid |

## Source Structure

1 Rust source file(s) in `src/`.
Language: Rust

## Cross-Repo References

- [ternary-core](https://github.com/SuperInstance/ternary-core) — shared Z₃ traits
- [ternary-types](https://github.com/SuperInstance/ternary-types) — type-level encodings
- [Full SuperInstance fleet](https://github.com/orgs/SuperInstance/repositories?q=ternary)
