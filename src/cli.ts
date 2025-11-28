#!/usr/bin/env node
import 'dotenv/config'
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { webcrypto } from '@substrate-system/one-webcrypto'
import * as u from 'uint8arrays'
import chalk from 'chalk'

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

await yargs(hideBin(process.argv))
    .command(
        'keys [algorithm]',
        'Create a new keypair',
        (yargs) => {
            return yargs
                .positional('algorithm', {
                    describe: 'The algorithm to use for the new key',
                    type: 'string',
                    choices: ['ed25519', 'rsa'],
                    default: 'ed25519'
                })
                .option('format', {
                    alias: 'f',
                    describe: 'Output format for the keys',
                    type: 'string',
                    choices: ['base64', 'base64pad', 'hex', 'base64url', 'base58btc'],
                    default: 'base58btc'
                })
        },
        async (argv) => {
            await keysCommand({
                algorithm: argv.algorithm as 'ed25519' | 'rsa',
                format: argv.format as u.SupportedEncodings
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
                        'utf8', 'ascii'],
                    default: 'base58btc'
                })
                .option('input-format', {
                    alias: 'i',
                    describe: 'The format of the input string',
                    type: 'string',
                    choices: ['base64', 'hex', 'base64url', 'base58btc',
                        'utf8', 'ascii'],
                    default: 'utf8'
                })
        },
        async (argv) => {
            // Read from stdin
            const input = (await readStdin()).trim()

            const result = await encodeCommand(
                input,
                argv['input-format'] as u.SupportedEncodings,
                argv['output-format'] as u.SupportedEncodings
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
                        'base58btc', 'ascii'],
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
    .demandCommand(1, 'You must provide a command')
    .help()
    .alias('help', 'h')
    .parse()

/**
 * Generate a new keypair.
 */
async function keysCommand (args:{
    algorithm:'ed25519'|'rsa',
    format?:u.SupportedEncodings
} = { algorithm: 'ed25519', format: 'base58btc' }) {
    const format = args.format || 'base58btc'

    try {
        if (args.algorithm === 'ed25519') {
            const keypair = await webcrypto.subtle.generateKey(
                {
                    name: 'Ed25519',
                    namedCurve: 'Ed25519'
                },
                true,
                ['sign', 'verify']
            )

            const publicKey = await webcrypto.subtle.exportKey(
                'raw',
                keypair.publicKey
            )
            const privateKey = await webcrypto.subtle.exportKey(
                'pkcs8',
                keypair.privateKey
            )

            console.log(JSON.stringify({
                publicKey: formatOutput(new Uint8Array(publicKey), format),
                privateKey: formatOutput(new Uint8Array(privateKey), format)
            }))
        } else if (args.algorithm === 'rsa') {
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

            const publicKey = await webcrypto.subtle.exportKey(
                'spki',
                keypair.publicKey
            )
            const privateKey = await webcrypto.subtle.exportKey(
                'pkcs8',
                keypair.privateKey
            )

            console.log(JSON.stringify({
                publicKey: formatOutput(new Uint8Array(publicKey), format),
                privateKey: formatOutput(new Uint8Array(privateKey), format)
            }))
        }
    } catch (err) {
        console.error(chalk.red('Error generating keypair:'), err)
        process.exit(1)
    }
}

/**
 * Format output with multibase prefix for base58btc.
 */
function formatOutput (bytes:Uint8Array, format:u.SupportedEncodings):string {
    if (format === 'base58btc') {
        return 'z' + u.toString(bytes, format)
    }
    return u.toString(bytes, format)
}

/**
 * Encode a string in one format to a different format.
 */
async function encodeCommand (
    input:string,
    inputFormat:u.SupportedEncodings,
    outputFormat:u.SupportedEncodings
):Promise<string> {
    try {
        // First decode from the input format to Uint8Array
        const bytes = u.fromString(input, inputFormat)

        // Then encode to the output format
        const output = u.toString(bytes, outputFormat)

        return output
    } catch (err) {
        console.error(chalk.red('Error encoding:'), err)
        process.exit(1)
    }
}

/**
 * Decode a string from a given format to UTF-8.
 */
async function decodeCommand (
    input:string,
    inputFormat:u.SupportedEncodings
):Promise<string> {
    try {
        // Decode from the input format to Uint8Array
        const bytes = u.fromString(input, inputFormat)

        // Convert to UTF-8 string
        const output = u.toString(bytes, 'utf8')

        return output
    } catch (err) {
        console.error(chalk.red('Error decoding:'), err)
        process.exit(1)
    }
}
