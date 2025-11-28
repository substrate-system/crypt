# crypt

[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/crypt/nodejs.yml?style=flat-square)](https://github.com/substrate-system/crypt/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/crypt?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/crypt)](https://packagephobia.com/result?p=@substrate-system/crypt)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)

A CLI tool for creating keys and encoding strings.


<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
  * [Generate and Encode Keys](#generate-and-encode-keys)
  * [Show Help Text](#show-help-text)
- [Commands](#commands)
  * [`keys [algorithm]`](#keys-algorithm)
  * [`encode [output-format]`](#encode-output-format)
  * [`decode [input-format]`](#decode-input-format)

<!-- tocstop -->

</details>

## Install

Install globally:

```sh
npm i -g @substrate-system/crypt
```

Or install locally, and run with `npx`:

```sh
npm i -D @substrate-system/crypt
npx crypt keys
```

### Generate and Encode Keys

This will print a JSON string with `{ publickKey, privateKey }` to `stdout`.
The default string encoding is `base58btc`. You can pass in a different encoding
to use for the output with the `-f` or `--format` option.

```sh
# Generate Ed25519 keypair
npx crypt keys

# Generate RSA keypair in base58btc format
npx crypt keys rsa --format base58btc

# Convert between encoding formats via stdin
echo "Hello World" | npx crypt encode base64
# => SGVsbG8gV29ybGQ

echo "SGVsbG8gV29ybGQ" | npx crypt encode utf8 -i base64
# => Hello World

echo "SGVsbG8gV29ybGQ" | npx crypt encode hex -i base64
# => 48656c6c6f20576f726c64
```

### Show Help Text

```sh
npx crypt --help

# Show help for a specific command
npx crypt keys --help
npx crypt encode --help
```

---

## Commands

### `keys [algorithm]`

Generate a new cryptographic keypair, by default `ed25519`.
Output is a JSON string of `{ publicKey, privateKey }`, where each key
is encoded as `base58`.


#### Arguments

* `algorithm` - The algorithm to use (default: `ed25519`)
  - `ed25519` - Ed25519 elliptic curve
  - `rsa` - RSA-PSS 2048-bit

#### Options

* `-f, --format` - Output format for the keys (default: `base58btc`)
  - `base58btc` - Base58 with multibase prefix (`z`)
  - `base64` - Standard base64 encoding
  - `base64pad` - Padded base64 encoding
  - `hex` - Hexadecimal encoding
  - `base64url` - URL-safe base64 encoding

#### `keys` Example

```sh
# Generate Ed25519 keypair in base58btc (default)
npx crypt keys

# Generate RSA keypair in hexadecimal
npx crypt keys rsa --format hex

# Generate Ed25519 keypair in base64pad
npx crypt keys ed25519 -f base64pad
```

---

### `encode [output-format]`

Convert a string from one encoding format to another. Reads input from stdin.

#### Arguments

* `output-format` - The desired output format (default: `base58btc`)
  - `base58btc`, `base64`, `hex`, `base64url`, `utf8`, `ascii`

#### Options

* `-i, --input-format` - The format of the input string (default: `utf8`)
  - `base64`, `hex`, `base64url`, `base58btc`, `utf8`, `ascii`

#### `encode` Example

```sh
# Encode UTF-8 text to base58btc (default)
echo "Hello World" | npx crypt encode

# Encode UTF-8 to base64
echo "Hello World" | npx crypt encode base64

# Convert base64 to hex
echo "SGVsbG8gV29ybGQ=" | npx crypt encode hex -i base64

# Convert hex to base58btc
echo "48656c6c6f" | npx crypt encode base58btc -i hex

# Pipe between commands
npx crypt keys | jq -r .publicKey | npx crypt encode hex -i base58btc
```

---

### `decode [input-format]`

Decode a string from a given encoding format to UTF-8. Reads input from stdin.

#### Arguments

* `input-format` - The format of the input string (default: `base64`)
  - `base64`, `base64pad`, `hex`, `base64url`, `base58btc`, `ascii`

#### `decode` Example

```sh
# Decode base64 to UTF-8 (default)
echo "SGVsbG8gV29ybGQ=" | npx crypt decode

# Decode base64pad to UTF-8
echo "SGVsbG8gV29ybGQ=" | npx crypt decode base64pad
# => 'Hello World'

# Decode hex to UTF-8
echo "48656c6c6f20576f726c64" | npx crypt decode hex

# Decode base58btc to UTF-8
echo "JxF12TrwUP45BMd" | npx crypt decode base58btc
```
