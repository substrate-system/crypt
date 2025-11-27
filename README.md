# crypt

[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/crypt/nodejs.yml?style=flat-square)](https://github.com/substrate-system/crypt/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/crypt?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/session-cookie)](https://packagephobia.com/result?p=@substrate-system/session-cookie)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)

A CLI tool for creating and encoding keys.


<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
- [Example](#example)
  * [Generate and Encode Keys](#generate-and-encode-keys)
  * [Show Help Text](#show-help-text)
- [Commands](#commands)
  * [`keys [algorithm]`](#keys-algorithm)
  * [`encode `](#encode--)

<!-- tocstop -->

</details>

## Install

```sh
npm i -D @substrate-system/crypt
```

---

## Example

Install globall:

```sh
npm i -g @substrate-system/crypt
```

Or install locally, and run with `npx`:

```sh
npm i -D @substrate-system/crypt
npx crypt keys
```

### Generate and Encode Keys

```sh
# Generate Ed25519 keypair
npx crypt keys

# Generate RSA keypair in base58btc format
npx crypt keys rsa --format base58btc

# Convert between encoding formats
npx crypt encode "example" base64
npx crypt encode "ZXhhbXBsZQ==" hex -i base64
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

Generate a new cryptographic keypair.

**Arguments:**
- `algorithm` - The algorithm to use (default: `ed25519`)
  - `ed25519` - Ed25519 elliptic curve
  - `rsa` - RSA-PSS 2048-bit

**Options:**
- `-f, --format` - Output format for the keys (default: `base64`)
  - `base64` - Standard base64 encoding
  - `hex` - Hexadecimal encoding
  - `base64url` - URL-safe base64 encoding
  - `base58btc` - Base58 with multibase prefix (`z`)

#### `keys` Example

```sh
# Generate Ed25519 keypair in base64 (default)
node src/cli.ts keys

# Generate RSA keypair in hexadecimal
node src/cli.ts keys rsa --format hex

# Generate Ed25519 keypair in multibase base58btc
node src/cli.ts keys ed25519 -f base58btc
```

---

### `encode <input> <output-format>`

Convert a string from one encoding format to another.

**Arguments:**
- `input` - The input string to encode
- `output-format` - The desired output format
  - `base64`, `hex`, `base64url`, `base58btc`, `utf8`, `ascii`

**Options:**
- `-i, --input-format` - The format of the input string (default: `utf8`)
  - `base64`, `hex`, `base64url`, `base58btc`, `utf8`, `ascii`

#### `encode` Example

```sh
# Encode UTF-8 text to base64
npx crypt encode "Hello World" base64

# Convert base64url to hex
npx crypt encode "SGVsbG8gV29ybGQ" hex --input-format base64url

# Convert hex to base58btc
npx crypt encode "48656c6c6f" base58btc -i hex

# Convert base64 to UTF-8
npx crypt encode "SGVsbG8gV29ybGQ=" utf8 -i base64
```
