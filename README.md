# crypt

[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/crypt/nodejs.yml?style=flat-square)](https://github.com/substrate-system/crypt/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/crypt?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/crypt)](https://packagephobia.com/result?p=@substrate-system/crypt)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)

A CLI tool for creating keys and encoding strings.
This exposes a command `crypt`.


<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
  * [Generate and Encode Keys](#generate-and-encode-keys)
  * [Show Help Text](#show-help-text)
- [Commands](#commands)
  * [`keys [algorithm]`](#keys-algorithm)
  * [`encode [output-format]`](#encode-output-format)
  * [`decode [input-format]`](#decode-input-format)
- [Key Format](#key-format)
  * [Multikey](#multikey)

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

For **Ed25519** keys, this will print a JSON string with
`{ publicKey, privateKey }` to `stdout`.
For **RSA** keys, the private key is written to a file (requires `-o` option)
and the public key is printed to `stdout`.

The default output format is `multi` (multikey format).
You can pass in a different encoding to use for the output with
the `-f` or `--format` option.

```sh
# Generate Ed25519 keypair (outputs both keys to stdout)
npx crypt keys

# Generate RSA keypair, write private key to file
npx crypt keys rsa -o private.pem

# Generate RSA keypair in JWK format (outputs both keys to stdout)
npx crypt keys rsa -f jwk

# Generate Ed25519 keypair with DID format
npx crypt keys -f did

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

**Ed25519 keys**: Output is a JSON string of `{ publicKey, privateKey }`
to stdout. Private keys are in JWK format. If `-o` is specified, the
private key is written to the file and only the public key is printed to stdout.

**RSA keys**: Requires `-o` option to specify output file for the private key
(in PKCS#8 PEM format), unless using `-f jwk` which outputs both keys as
JSON to stdout.

#### Arguments

* `algorithm` - The algorithm to use (default: `ed25519`)
  - `ed25519` - Ed25519 elliptic curve
  - `rsa` - RSA-PSS 2048-bit

#### Options

* `-f, --format` - Output format for public key (default: `multi`)
  - `multi` - Multikey format with multibase encoding
  - `base58btc` - Base58 with multibase prefix (`z`)
  - `base64` - Standard base64 encoding
  - `base64pad` - Padded base64 encoding
  - `hex` - Hexadecimal encoding
  - `base64url` - URL-safe base64 encoding
  - `did` - Decentralized identifier format (`did:key:z...`)
  - `jwk` - JSON Web Key format (outputs both public and private keys)

* `-o, --output` - Output file for private key
  - **Required for RSA** (unless using `-f jwk`)
  - Optional for Ed25519
    (if specified, private key goes to file instead of stdout)
  - RSA private keys are written as PKCS#8 PEM format
  - Ed25519 private keys are written as JWK format

* `-m, --multi` - Use multibase encoding with prefixes (default: `false`)
  - When enabled, adds the appropriate
    [multibase](https://github.com/multiformats/multibase) prefix for the
    encoding format
  - Prefixes: `m` (base64), `M` (base64pad), `u` (base64url),
    `U` (base64urlpad), `z` (base58btc), `f` (hex)

#### `keys` Example

```sh
# Generate Ed25519 keypair in multikey format (default)
npx crypt keys
# => {"publicKey":"z6Mk...", "privateKey":{...JWK...}}

# Generate Ed25519 keypair in base58btc
npx crypt keys -f base58btc

# Generate Ed25519 keypair in DID format
npx crypt keys -f did
# => {"publicKey":"did:key:z6Mk...", "privateKey":{...JWK...}}

# Generate Ed25519 keypair, save private key to file
npx crypt keys -o private.json
# => {"publicKey":"z6Mk..."}
# (private.json contains the JWK)

# Generate RSA keypair, save private key to file as PEM
npx crypt keys rsa -o private.pem
# => {"publicKey":"z5Tc..."}
# (private.pem contains PKCS#8 PEM format)

# Generate RSA keypair in JWK format (both keys to stdout)
npx crypt keys rsa -f jwk
# => {"publicKey":{...JWK...}, "privateKey":{...JWK...}}

# Generate keypair with multibase encoding (adds prefixes)
npx crypt keys --format hex --multi
# => {"publicKey":"f8291f2...", "privateKey":{...JWK...}}

npx crypt keys --format base64 -m
# => {"publicKey":"mCKHyYn...", "privateKey":{...JWK...}}
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

* `-m, --multi` - Use multibase encoding with prefixes (default: `false`)
  - Add the appropriate [multibase](https://github.com/multiformats/multibase)
    prefix to the output.
  - Prefixes: `m` (base64), `u` (base64url), `z` (base58btc), `f` (hex)

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

# Encode with multibase prefixes
echo "Hello World" | npx crypt encode base64 --multi
# => mSGVsbG8gV29ybGQ

echo "Hello World" | npx crypt encode hex -m
# => f48656c6c6f20576f726c64

echo "Hello World" | npx crypt encode base64url --multi
# => uSGVsbG8gV29ybGQ

# convert "multikey" format to hex format
echo "z6MkiLr..." | npx crypt encode hex -i multi
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

## Key Format

### Multikey

This uses [Multikey format](https://www.w3.org/TR/cid-1.0/#Multikey) strings.
[Multikey format](https://www.w3.org/TR/cid-1.0/#Multikey), is
a generic, self-describing,
[multicodec-based](https://www.w3.org/TR/cid-1.0/#multibase-0)
public key encoding.

```ts
import { base58btc } from 'multiformats/bases/base58'
import * as varint from "multiformats/src/varint"

// Suppose you have a raw public-key Buffer/Uint8Array
const rawKeyBytes = /* ... */

// --- helper: varint-encoded multicodec prefix for ed25519-pub ---
// multicodec code for ed25519-pub is 0xED (237).
// varint encoding for 237 is two bytes: 0xED 0x01
const ED25519_MULTICODEC_VARINT = Uint8Array.from([0xed, 0x01])
const out = new Uint8Array(ED25519_MULTICODEC_VARINT.length + rawPubKey.length)
out.set(ED25519_MULTICODEC_VARINT, 0)
out.set(rawKeyBytes, ED25519_MULTICODEC_VARINT.length)

// base58btc (multibase) encode
// multiformats' base58btc.encode typically returns a string that already
// uses the 'z'
let encoded = base58btc.encode(out)
encoded = encoded.startsWith('z') ? encoded : 'z' + encoded

// This yields something like "z6Mk…", same style as in the DID doc
console.log(encoded)

/**
 * Decode a Multikey multibase string (ed25519-pub) back to raw key bytes.
 * Returns an object { algCode, rawKey } where algCode is the multicodec
 * numeric code.
 */
function decodeMultikey (multibaseStr):{ } {
  // Accept with/without leading 'z' — multiformats will accept
  // without the explicit 'z' only if decoder used directly.
  const cleaned = (multibaseStr.startsWith('z') ?
    multibaseStr :
    'z' + multibaseStr)
  const decoded = base58btc.decode(cleaned)  // returns Uint8Array

  // read varint (we know ed25519 varint is two bytes: 0xed 0x01)
  // robust approach: parse varint; here we handle single or two-byte
  // varints for small values
  let i = 0
  let code = 0
  let shift = 0
  while (i < decoded.length) {
    const b = decoded[i++]
    code |= (b & 0x7f) << shift
    if ((b & 0x80) === 0) break
    shift += 7
  }
  const rawKey = decoded.slice(i)  // remainder is the raw key bytes
  return { multicodec: code, rawKey }
}
```
