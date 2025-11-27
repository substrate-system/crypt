import { test } from '@substrate-system/tapzero'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import * as u from 'uint8arrays'

const CLI_PATH = join(process.cwd(), 'dist', 'cli.js')

// Test the `keys` command
test('keys command generates Ed25519 keypair by default', async t => {
    const result = await runCLI(['keys'])

    t.equal(result.code, 0, 'command should exit with code 0')
    t.ok(result.stdout.includes('Ed25519 keypair generated'),
        'should show Ed25519 keypair generation message')
    t.ok(result.stdout.includes('Public Key:'),
        'should show public key label')
    t.ok(result.stdout.includes('Private Key'),
        'should show private key label')
})

test('keys command generates RSA keypair when specified', async t => {
    const result = await runCLI(['keys', 'rsa'])

    t.equal(result.code, 0, 'command should exit with code 0')
    t.ok(result.stdout.includes('RSA keypair generated'),
        'should show RSA keypair generation message')
    t.ok(result.stdout.includes('Public Key'),
        'should show public key label')
    t.ok(result.stdout.includes('Private Key'),
        'should show private key label')
})

test('keys command outputs in base64 format by default', async t => {
    const result = await runCLI(['keys', 'ed25519'])

    t.equal(result.code, 0, 'command should exit with code 0')

    // Extract the public key (first non-label line after "Public Key:")
    const lines = result.stdout.split('\n')
    const pubKeyIndex = lines.findIndex(line => line.includes('Public Key:'))
    const pubKey = lines[pubKeyIndex + 1]?.trim()

    // Base64 should only contain valid base64 characters
    t.ok(pubKey && /^[A-Za-z0-9+/]+=*$/.test(pubKey),
        'should output valid base64')
})

test('keys command outputs in hex format when specified', async t => {
    const result = await runCLI(['keys', 'ed25519', '--format', 'hex'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const lines = result.stdout.split('\n')
    const pubKeyIndex = lines.findIndex(line => line.includes('Public Key:'))
    const pubKey = lines[pubKeyIndex + 1]?.trim()

    // Hex should only contain 0-9, a-f
    t.ok(pubKey && /^[0-9a-f]+$/.test(pubKey),
        'should output valid hexadecimal')
})

test('keys command outputs in base58btc with multibase prefix', async t => {
    const result = await runCLI(['keys', 'ed25519', '-f', 'base58btc'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const lines = result.stdout.split('\n')
    const pubKeyIndex = lines.findIndex(line => line.includes('Public Key:'))
    const pubKey = lines[pubKeyIndex + 1]?.trim()

    // Base58btc with multibase should start with 'z'
    t.ok(pubKey && pubKey.startsWith('z'),
        'should have multibase prefix "z"')
    t.ok(pubKey && /^z[1-9A-HJ-NP-Za-km-z]+$/.test(pubKey),
        'should be valid base58btc with multibase prefix')
})

test('keys command shows help with --help flag', async t => {
    const result = await runCLI(['keys', '--help'])

    t.equal(result.code, 0, 'help command should exit with code 0')
    t.ok(result.stdout.includes('Create a new keypair'),
        'should show command description')
    t.ok(result.stdout.includes('algorithm'),
        'should mention algorithm parameter')
    t.ok(result.stdout.includes('format'),
        'should mention format option')
})

// Test the `encode` command
test('encode command converts UTF-8 to base64', async t => {
    const input = 'Hello World'
    const result = await runCLI(['encode', input, 'base64'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'utf8'), 'base64')

    t.equal(output, expected, 'should correctly encode UTF-8 to base64')
})

test('encode command converts base64 to hex', async t => {
    const input = 'SGVsbG8gV29ybGQ='
    const result = await runCLI([
        'encode',
        input,
        'hex',
        '--input-format',
        'base64'
    ])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'base64'), 'hex')

    t.equal(output, expected, 'should correctly convert base64 to hex')
})

test('encode command converts hex to base58btc', async t => {
    const input = '48656c6c6f'
    const result = await runCLI([
        'encode',
        input,
        'base58btc',
        '-i',
        'hex'
    ])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'hex'), 'base58btc')

    t.equal(output, expected, 'should correctly convert hex to base58btc')
})

test('encode command converts base64url to hex', async t => {
    const input = 'SGVsbG8gV29ybGQ'
    const result = await runCLI([
        'encode',
        input,
        'hex',
        '--input-format',
        'base64url'
    ])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'base64url'), 'hex')

    t.equal(output, expected,
        'should correctly convert base64url to hex')
})

test('encode command converts base64 to UTF-8', async t => {
    const input = 'SGVsbG8gV29ybGQ='
    const result = await runCLI([
        'encode',
        input,
        'utf8',
        '-i',
        'base64'
    ])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()

    t.equal(output, 'Hello World',
        'should correctly convert base64 to UTF-8')
})

test('encode command requires input and output-format arguments', async t => {
    const result = await runCLI(['encode'])

    t.ok(result.code !== 0,
        'command should exit with non-zero code when missing arguments')
    t.ok(result.stderr.includes('Not enough non-option arguments'),
        'should show error about missing arguments')
})

test('encode command shows help with --help flag', async t => {
    const result = await runCLI(['encode', '--help'])

    t.equal(result.code, 0, 'help command should exit with code 0')
    t.ok(result.stdout.includes('Encode a string'),
        'should show command description')
    t.ok(result.stdout.includes('input'),
        'should mention input parameter')
    t.ok(result.stdout.includes('output-format'),
        'should mention output-format parameter')
    t.ok(result.stdout.includes('input-format'),
        'should mention input-format option')
})

// General CLI behavior
test('CLI shows error when called without arguments', async t => {
    const result = await runCLI([])

    t.ok(result.code !== 0,
        'should exit with non-zero code when no command provided')
    t.ok(result.stderr.includes('You must provide a command'),
        'should show message about needing a command')
})

test('CLI shows help with --help flag', async t => {
    const result = await runCLI(['--help'])

    t.equal(result.code, 0, 'help command should exit with code 0')
    t.ok(result.stdout.includes('keys'), 'should list keys command')
    t.ok(result.stdout.includes('encode'), 'should list encode command')
})

/**
 * Helper function to run the CLI command and capture output
 */
function runCLI (args:string[]):Promise<{
    stdout:string
    stderr:string
    code:number | null
}> {
    return new Promise((resolve) => {
        const child = spawn('node', [CLI_PATH, ...args])
        let stdout = ''
        let stderr = ''

        child.stdout.on('data', (data) => {
            stdout += data.toString()
        })

        child.stderr.on('data', (data) => {
            stderr += data.toString()
        })

        child.on('close', (code) => {
            resolve({ stdout, stderr, code })
        })
    })
}
