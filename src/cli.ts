#!/usr/bin/env node
import 'dotenv/config'
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { webcrypto } from '@substrate-system/one-webcrypto'
import * as u from 'uint8arrays'
import { publicKeyToDid } from '@substrate-system/keys/crypto'
import * as multikey from '@substrate-system/multikey'
import chalk from 'chalk'
import { writeFileSync } from 'node:fs'
import { createPrivateKey, sign as cryptoSign } from 'node:crypto'

// Only run CLI if this file is being executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    await yargs(hideBin(process.argv))
        .command(
            'keys [algorithm]',
            'Create a new keypair',
            (yargs) => {
                return yargs
                    .positional('algorithm', {
                        describe: 'The algorithm to use for the new key',
                        type: 'string',
                        choices: ['ed25519', 'x25519', 'rsa'],
                        default: 'ed25519'
                    })
                    .option('format', {
                        alias: 'f',
                        describe: 'Output format',
                        type: 'string',
                        choices: ['raw', 'jwk'],
                        default: 'raw'
                    })
                    .option('output', {
                        alias: 'o',
                        describe: 'Output file for private key (required for RSA unless using -f jwk; optional for Ed25519/X25519)',
                        type: 'string'
                    })
                    .option('multi', {
                        alias: 'm',
                        describe: 'Use multibase encoding with prefixes',
                        type: 'boolean',
                        default: false
                    })
            },
            async (argv) => {
                await keysCommand({
                    algorithm: argv.algorithm as 'ed25519'|'x25519'|'rsa',
                    format: argv.format as 'raw'|'jwk',
                    output: argv.output as string|undefined,
                    useMultibase: argv.multi as boolean
                })
            }
        )
        .command(
            'encode [output-format]',
            'Encode a string from one format to another',
            (yargs) => {
                return yargs
                    .positional('output-format', {
                        describe: 'The desired output format',
                        type: 'string',
                        choices: ['base64', 'hex', 'base64url', 'base58btc',
                            'utf8', 'ascii', 'multi'],
                        default: 'base64url'
                    })
                    .option('input-format', {
                        alias: 'i',
                        describe: 'The format of the input string',
                        type: 'string',
                        choices: ['base64', 'hex', 'base64url', 'base58btc',
                            'utf8', 'ascii', 'multi'],
                        default: 'utf8'
                    })
                    .option('type', {
                        alias: 't',
                        describe: 'Key type (required when output-format is multi)',
                        type: 'string',
                        choices: ['ed25519', 'rsa']
                    })
                    .option('multi', {
                        alias: 'm',
                        describe: 'Use multibase encoding with prefixes',
                        type: 'boolean',
                        default: false
                    })
                    .check((argv) => {
                        if (argv['output-format'] === 'multi' && !argv.type) {
                            throw new Error('--type is required when ' +
                            'output-format is "multi"')
                        }
                        return true
                    })
            },
            async (argv) => {
            // Read from stdin
                const input = (await readStdin()).trim()

                const result = await encodeCommand(
                    input,
                argv['input-format'] as u.SupportedEncodings|'multi',
                argv['output-format'] as u.SupportedEncodings|'multi',
                argv.multi as boolean,
                argv.type as 'ed25519'|'rsa'|undefined
                )
                console.log(result)
            }
        )
        .command(
            'decode [input-format]',
            'Decode a string to UTF-8',
            (yargs) => {
                return yargs
                    .positional('input-format', {
                        describe: 'The format of the input string',
                        type: 'string',
                        choices: ['base64', 'base64pad', 'hex', 'base64url',
                            'base58btc', 'ascii', 'multi'],
                        default: 'base64'
                    })
            },
            async (argv) => {
            // Read from stdin
                const input = (await readStdin()).trim()

                const result = await decodeCommand(
                    input,
                argv['input-format'] as u.SupportedEncodings
                )
                console.log(result)
            }
        )
        .command(
            'sign [message]',
            'Sign a string with a private key',
            (yargs) => {
                return yargs
                    .positional('message', {
                        describe: 'The message to sign (or read from stdin if omitted)',
                        type: 'string'
                    })
                    .option('key', {
                        alias: 'k',
                        describe: 'Private key seed (base64url encoded)',
                        type: 'string',
                        demandOption: true
                    })
            },
            async (argv) => {
            // If message is not provided as argument, read from stdin
                let message:string
                if (argv.message) {
                    message = argv.message
                } else {
                    message = (await readStdin()).trim()
                }

                const result = await signCommand(
                    message,
                argv.key as string
                )
                console.log(result)
            }
        )
        .demandCommand(1, 'You must provide a command')
        .help()
        .alias('help', 'h')
        .parse()
}

/**
 * Generate a new keypair.
 * Core API function that returns keypair data.
 * For Ed25519: By default (format 'raw'), private keys are exported as base64url-encoded seeds,
 *              public keys as multikey format. Can use format 'jwk' for JWK format.
 * For X25519: Same as Ed25519 - private keys are exported as base64url-encoded seeds,
 *             public keys as base64url-encoded keys. Can use format 'jwk' for JWK format.
 * For RSA: Private keys are exported as PKCS#8 PEM or JWK,
 *          public keys as multikey format or JWK.
 */
export async function keys (args:{
    algorithm?:'ed25519'|'x25519'|'rsa',
    format?:'raw'|'jwk',
    useMultibase?:boolean
} = {}):Promise<{
    publicKey: string | object,
    privateKey?: string | object,
    privateKeyPem?: string
}> {
    const algorithm = args.algorithm || 'ed25519'
    const publicFormat = args.format || 'raw'
    const useMultibase = args.useMultibase || false

    // 'raw' format only supported for Ed25519 and X25519
    if (algorithm === 'rsa' && publicFormat === 'raw') {
        throw new Error('"raw" format is only supported for Ed25519 and X25519 keys. Use format "jwk" for RSA keys.')
    }

    if (algorithm === 'ed25519') {
        const keypair = await webcrypto.subtle.generateKey(
            {
                name: 'Ed25519',
                namedCurve: 'Ed25519'
            },
            true,
            ['sign', 'verify']
        )

        const privateKeyJwk = await webcrypto.subtle.exportKey(
            'jwk',
            keypair.privateKey
        )

        if (publicFormat === 'jwk') {
            // Return private key JWK directly (which contains public key in 'x' field)
            return privateKeyJwk as any
        } else {
            // For 'raw' format, use multikey for public key
            const publicKey = await webcrypto.subtle.exportKey(
                'raw',
                keypair.publicKey
            )
            const publicKeyFormatted = await formatOutput(
                new Uint8Array(publicKey),
                'multi',
                useMultibase,
                'ed25519',
                true
            )

            // Extract seed from JWK 'd' field (already base64url encoded)
            if (!privateKeyJwk.d) {
                throw new Error('Private key JWK missing "d" field')
            }

            return {
                publicKey: publicKeyFormatted,
                privateKey: privateKeyJwk.d
            }
        }
    } else if (algorithm === 'x25519') {
        const keypair = await webcrypto.subtle.generateKey(
            {
                name: 'X25519',
                namedCurve: 'X25519'
            },
            true,
            ['deriveKey', 'deriveBits']
        )

        const privateKeyJwk = await webcrypto.subtle.exportKey(
            'jwk',
            keypair.privateKey
        )

        if (publicFormat === 'jwk') {
            // Return private key JWK directly (which contains public key in 'x' field)
            return privateKeyJwk as any
        } else {
            // For 'raw' format, export keys as base64url
            const publicKey = await webcrypto.subtle.exportKey(
                'raw',
                keypair.publicKey
            )
            const publicKeyEncoded = u.toString(
                new Uint8Array(publicKey),
                'base64url'
            )

            // Extract seed from JWK 'd' field (already base64url encoded)
            if (!privateKeyJwk.d) {
                throw new Error('Private key JWK missing "d" field')
            }

            return {
                publicKey: publicKeyEncoded,
                privateKey: privateKeyJwk.d
            }
        }
    } else if (algorithm === 'rsa') {
        const keypair = await webcrypto.subtle.generateKey(
            {
                name: 'RSA-PSS',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            ['sign', 'verify']
        )

        if (publicFormat === 'jwk') {
            // Return private key JWK directly (contains public key components)
            const privateKey = await webcrypto.subtle.exportKey(
                'jwk',
                keypair.privateKey
            )

            return privateKey as any
        } else {
            // For 'raw' format, export as PKCS#8 PEM and multikey
            const publicKey = await webcrypto.subtle.exportKey(
                'spki',
                keypair.publicKey
            )
            const privateKey = await webcrypto.subtle.exportKey(
                'pkcs8',
                keypair.privateKey
            )

            const pem = pkcs8ToPem(new Uint8Array(privateKey))
            const publicKeyFormatted = await formatOutput(
                new Uint8Array(publicKey),
                'multi',
                useMultibase,
                'rsa',
                true
            )

            return {
                publicKey: publicKeyFormatted,
                privateKeyPem: pem
            }
        }
    }

    throw new Error(`Unsupported algorithm: ${algorithm}`)
}

/**
 * CLI command handler for keys command.
 */
async function keysCommand (args:{
    algorithm:'ed25519'|'x25519'|'rsa',
    format?:'raw'|'jwk',
    output?:string,
   useMultibase?:boolean
} = { algorithm: 'ed25519', format: 'raw' }) {
    const publicFormat = args.format || 'raw'

    // For RSA, require output file unless format is 'jwk'
    if (args.algorithm === 'rsa' && publicFormat !== 'jwk' && !args.output) {
        console.error(chalk.red('Error: RSA keys require an output file. Use -o or --output to specify the private key file, or use -f jwk for JWK output.'))
        process.exit(1)
    }

    try {
        const result = await keys(args)

        if (args.output) {
            // Write private key to file
            if ('privateKeyPem' in result) {
                // RSA PEM format
                writeFileSync(args.output, result.privateKeyPem as string, 'utf8')
            } else if (publicFormat === 'jwk') {
                // JWK format - result is the JWK itself
                writeFileSync(args.output, JSON.stringify(result, null, 2), 'utf8')
                // For JWK, also output the public key portion to stdout
                console.log(JSON.stringify({ publicKey: result }))
                return
            } else if ('privateKey' in result && typeof result.privateKey === 'string') {
                // Raw format (seed)
                writeFileSync(args.output, result.privateKey, 'utf8')
            }

            // Output only public key to stdout (for raw/PEM formats)
            if ('publicKey' in result) {
                console.log(JSON.stringify({ publicKey: result.publicKey }))
            }
        } else {
            // Output to stdout
            if (publicFormat === 'jwk') {
                // For JWK format, result is the JWK directly
                console.log(JSON.stringify(result))
            } else {
                // For raw format, result has publicKey and privateKey
                console.log(JSON.stringify(result))
            }
        }
    } catch (err) {
        console.error(chalk.red('Error generating keypair:'), err)
        process.exit(1)
    }
}

/**
 * Get the multibase prefix for a given encoding format.
 * @see https://github.com/multiformats/multibase
 */
function getMultibasePrefix (format:u.SupportedEncodings):string {
    const prefixes:Record<string, string> = {
        base64: 'm',
        base64pad: 'M',
        base64url: 'u',
        base64urlpad: 'U',
        base58btc: 'z',
        hex: 'f',
        ascii: '',
        utf8: ''
    }
    return prefixes[format] || ''
}

/**
 * Detect the encoding format from a multibase prefix.
 * @see https://github.com/multiformats/multibase
 */
function detectMultibaseFormat (input:string):{
    format:u.SupportedEncodings,
    data:string
} {
    if (input.length === 0) {
        throw new Error('Empty input string')
    }

    const prefix = input[0]
    const data = input.slice(1)

    const formatMap:Record<string, u.SupportedEncodings> = {
        m: 'base64',
        M: 'base64pad',
        u: 'base64url',
        U: 'base64urlpad',
        z: 'base58btc',
        f: 'hex'
    }

    const format = formatMap[prefix]
    if (!format) {
        throw new Error(`Unknown multibase prefix: ${prefix}`)
    }

    return { format, data }
}

/**
 * Encode a string in one format to a different format.
 * Core API function that returns the encoded string.
 */
export async function encode (
    input:string,
    options:{
        inputFormat?:u.SupportedEncodings|'multi',
        outputFormat:u.SupportedEncodings|'multi',
        useMultibase?:boolean,
        keyType?:'ed25519'|'rsa'
    }
):Promise<string> {
    const inputFormat = options.inputFormat || 'utf8'
    const outputFormat = options.outputFormat
    const useMultibase = options.useMultibase || false
    const keyType = options.keyType

    let bytes:Uint8Array

    // Handle multibase input format
    if (inputFormat === 'multi') {
        const { format, data } = detectMultibaseFormat(input)
        bytes = u.fromString(data, format)
    } else {
        // First decode from the input format to Uint8Array
        bytes = u.fromString(input, inputFormat)
    }

    if (outputFormat === 'multi') {
        // Strip multicodec prefix, since `formatOutput` will add it
        // Ed25519 varint prefix: [237, 1] (0xED, 0x01)
        // RSA varint prefix: [133, 36] (0x85, 0x24) encoding of 0x1205
        let keyBytes = bytes
        if (bytes.length > 2) {
            // Check for Ed25519 multicodec prefix (varint: 0xED, 0x01)
            if (bytes[0] === 0xed && bytes[1] === 0x01) {
                keyBytes = bytes.slice(2)
            } else if (bytes[0] === 0x85 && bytes[1] === 0x24) {
                // Check for RSA multicodec prefix (varint: 0x85, 0x24)
                keyBytes = bytes.slice(2)
            }
        }
        // For encode command, we're not dealing with SPKI format
        return formatOutput(keyBytes, 'multi', false, keyType, false)
    }

    // Then encode to the output format
    const output = u.toString(bytes, outputFormat)

    if (useMultibase) {
        const prefix = getMultibasePrefix(outputFormat)
        return prefix + output
    }

    return output
}

/**
 * CLI command handler for encode command.
 */
async function encodeCommand (
    input:string,
    inputFormat:u.SupportedEncodings|'multi',
    outputFormat:u.SupportedEncodings|'multi',
    useMultibase = false,
    keyType?:'ed25519'|'rsa'
):Promise<string> {
    try {
        return await encode(input, {
            inputFormat,
            outputFormat,
            useMultibase,
            keyType
        })
    } catch (err) {
        console.error(chalk.red('Error encoding:'), err)
        process.exit(1)
    }
}

/**
 * Decode a string from a given format to UTF-8.
 * Core API function that returns the decoded string.
 */
export async function decode (
    input:string,
    options:{ inputFormat:u.SupportedEncodings }
):Promise<string> {
    const inputFormat = options.inputFormat

    // Decode from the input format to Uint8Array
    const bytes = u.fromString(input, inputFormat)

    // Convert to UTF-8 string
    return u.toString(bytes, 'utf8')
}

/**
 * CLI command handler for decode command.
 */
async function decodeCommand (
    input:string,
    inputFormat:u.SupportedEncodings
):Promise<string> {
    try {
        return await decode(input, { inputFormat })
    } catch (err) {
        console.error(chalk.red('Error decoding:'), err)
        process.exit(1)
    }
}

/**
 * Sign a message with a private key seed.
 * Core API function that returns the signature.
 */
export async function sign (
    message:string,
    options:{ key:string }
):Promise<string> {
    const privateKeySeed = options.key

    // Validate that message is not empty
    if (!message || message.length === 0) {
        throw new Error('Message cannot be empty')
    }

    // Create a JWK with just the private key component
    // Node.js crypto can derive the public key from the private key
    const privateKeyJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        d: privateKeySeed,
        x: '' // Will be derived by Node.js
    }

    // Create a KeyObject from the JWK
    const privateKey = createPrivateKey({
        key: privateKeyJwk,
        format: 'jwk'
    })

    // Convert message to bytes
    const messageBytes = u.fromString(message, 'utf8')

    // Sign the message using Node.js crypto
    const signature = cryptoSign(null, messageBytes, privateKey)

    // Convert signature to base64url
    return u.toString(
        new Uint8Array(signature),
        'base64url'
    )
}

/**
 * CLI command handler for sign command.
 */
async function signCommand (
    message:string,
    privateKeySeed:string
):Promise<string> {
    try {
        return await sign(message, { key: privateKeySeed })
    } catch (err) {
        console.error(chalk.red('Error signing message:'), err)
        process.exit(1)
    }
}

/**
 * Format output with multibase prefix for base58btc, DID, or multi format.
 * Note: 'raw' format should be handled before calling this function (converted to 'multi' for public keys).
 */
async function formatOutput (
    bytes:Uint8Array,
    format:u.SupportedEncodings|'did'|'multi'|'raw',
    useMultibase = false,
    keyType?:'ed25519'|'rsa',
    isPublicKey = false
):Promise<string> {
    // 'raw' format for public keys should use multikey format
    if (format === 'raw') {
        format = 'multi'
    }

    if (format === 'did') {
        // For DID format, we need raw key bytes
        let keyBytes = bytes
        if (keyType === 'rsa' && isPublicKey) {
            // Extract raw key from SPKI format
            keyBytes = extractRawRsaKey(bytes)
        }
        return await publicKeyToDid(keyBytes, keyType)
    }

    if (format === 'multi') {
        // Multikey format: use the multikey package
        let keyBytes = bytes
        if (keyType === 'rsa' && isPublicKey) {
            // Extract raw key from SPKI format
            keyBytes = extractRawRsaKey(bytes)
        }
        if (!keyType) {
            throw new Error('keyType is required for multikey format')
        }
        return multikey.encode(keyBytes, keyType)
    }

    const encoded = u.toString(bytes, format as u.SupportedEncodings)

    if (useMultibase) {
        const prefix = getMultibasePrefix(format as u.SupportedEncodings)
        return prefix + encoded
    }

    // Legacy behavior: always add 'z' prefix for base58btc when not
    // using multibase flag
    if (format === 'base58btc') {
        return 'z' + encoded
    }

    return encoded
}

/**
 * Convert PKCS#8 DER bytes to PEM format.
 */
function pkcs8ToPem (der:Uint8Array):string {
    const base64 = u.toString(der, 'base64')
    const pem = [
        '-----BEGIN PRIVATE KEY-----',
        ...base64.match(/.{1,64}/g) || [],
        '-----END PRIVATE KEY-----'
    ].join('\n')
    return pem
}

/**
 * Read all data from stdin.
 */
async function readStdin ():Promise<string> {
    return new Promise((resolve, reject) => {
        const chunks:Buffer[] = []
        process.stdin.on('data', (chunk) => {
            chunks.push(chunk)
        })
        process.stdin.on('end', () => {
            resolve(Buffer.concat(chunks).toString())
        })
        process.stdin.on('error', reject)
    })
}

/**
 * Extract raw RSA public key from SPKI format.
 * SPKI structure contains algorithm identifier and other metadata.
 * We need just the raw key bytes for multikey encoding.
 */
function extractRawRsaKey (spkiBytes:Uint8Array):Uint8Array {
    // For RSA keys in SPKI format, the raw key is embedded in the BIT STRING
    // We need to parse the ASN.1 structure to extract it
    // This is a simplified parser that works for standard RSA SPKI keys

    // Skip to the BIT STRING that contains the actual public key
    // SPKI format: SEQUENCE { algorithm, publicKey BIT STRING }
    let offset = 0

    // Skip SEQUENCE tag and length
    if (spkiBytes[offset] !== 0x30) {
        throw new Error('Invalid SPKI format: expected SEQUENCE')
    }
    offset++

    // Skip length bytes (can be 1-4 bytes)
    const firstLengthByte = spkiBytes[offset++]
    if (firstLengthByte & 0x80) {
        const lengthOfLength = firstLengthByte & 0x7f
        offset += lengthOfLength
    }

    // Skip algorithm identifier SEQUENCE
    if (spkiBytes[offset] !== 0x30) {
        throw new Error('Invalid SPKI format: expected algorithm SEQUENCE')
    }
    offset++
    const algLengthByte = spkiBytes[offset++]
    let algLength = algLengthByte
    if (algLengthByte & 0x80) {
        const lengthOfLength = algLengthByte & 0x7f
        algLength = 0
        for (let i = 0; i < lengthOfLength; i++) {
            algLength = (algLength << 8) | spkiBytes[offset++]
        }
    }
    offset += algLength

    // Now we're at the BIT STRING containing the public key
    if (spkiBytes[offset] !== 0x03) {
        throw new Error('Invalid SPKI format: expected BIT STRING')
    }
    offset++

    // Read BIT STRING length
    const bitStringLengthByte = spkiBytes[offset++]
    let bitStringLength = bitStringLengthByte
    if (bitStringLengthByte & 0x80) {
        const lengthOfLength = bitStringLengthByte & 0x7f
        bitStringLength = 0
        for (let i = 0; i < lengthOfLength; i++) {
            bitStringLength = (bitStringLength << 8) | spkiBytes[offset++]
        }
    }

    // Skip the "number of unused bits" byte (should be 0)
    offset++

    // The remaining bytes are the actual RSA public key in PKCS#1 format
    return spkiBytes.slice(offset)
}
