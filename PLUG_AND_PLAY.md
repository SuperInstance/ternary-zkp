# PLUG_AND_PLAY — Zkp

> Zero-knowledge proofs over ternary fields (Z₃ arithmetic)

## 🚀 Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
ternary-zkp = { git = "https://github.com/SuperInstance/ternary-zkp" }
```

Use in your code:

```rust
use ternary_zkp::{TernaryField, prove, verify};

let statement = b"secret_value";
let proof = prove(statement);
assert!(verify(&proof));
```

## 📚 Available Documentation

| Document | Description |
|----------|-------------|
| `docs/FROM_BINARY.md` | Understanding ternary concepts as a binary programmer |
| `docs/MIGRATION.md` | Version migration guide |
| `docs/FUTURE-INTEGRATION.md` | Planned features and roadmap |

## 🔗 Integration

This crate is part of the [SuperInstance ternary fleet](https://github.com/SuperInstance). It uses the canonical `Ternary` type from `ternary-types` for cross-crate compatibility.

## 📄 License

MIT
