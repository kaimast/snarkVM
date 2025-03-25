# snarkvm-console-network

[![Crates.io](https://img.shields.io/crates/v/snarkvm-console-network.svg?color=neon)](https://crates.io/crates/snarkvm-console-network)
[![Authors](https://img.shields.io/badge/authors-Aleo-orange.svg)](https://aleo.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)

## Crate Features

* **default** - Sets all default features. Currently, this will only set `polycommit_full`.
* **polycommit_full** - TODO.
* **test** - Enable functionality specific to unit/integration tests
* **test_targets** - Lower the coinbase target for the mainnet. Used for development/test networks.
* **wasm** - Enable WebAssembly support. Should only be used when compiling against a `wasm32-*` target.
