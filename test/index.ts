import { test } from '@substrate-system/tapzero'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import * as u from 'uint8arrays'

const CLI_PATH = join(process.cwd(), 'dist', 'cli.js')

// Test the `keys` command
test('keys command generates Ed25519 keypair by default', async t => {
    const result = await runCLI(['keys'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    t.ok(output.publicKey, 'should have publicKey property')
    t.ok(output.privateKey, 'should have privateKey property')
    t.ok(output.publicKey.startsWith('z'),
        'should output base58btc with multibase prefix by default')
})

test('keys command generates RSA keypair when specified', async t => {
    const result = await runCLI(['keys', 'rsa'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    t.ok(output.publicKey, 'should have publicKey property')
    t.ok(output.privateKey, 'should have privateKey property')
})

test('keys command outputs in base58btc format by default', async t => {
    const result = await runCLI(['keys', 'ed25519'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    const pubKey = output.publicKey

    // Base58btc with multibase should start with 'z'
    t.ok(pubKey && pubKey.startsWith('z'),
        'should output base58btc with multibase prefix by default')
})

test('keys command outputs in hex format when specified', async t => {
    const result = await runCLI(['keys', 'ed25519', '--format', 'hex'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    const pubKey = output.publicKey

    // Hex should only contain 0-9, a-f
    t.ok(pubKey && /^[0-9a-f]+$/.test(pubKey),
        'should output valid hexadecimal')
})

test('keys command outputs in base64 with --format base64', async t => {
    const result = await runCLI(['keys', 'ed25519', '-f', 'base64'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    const pubKey = output.publicKey

    // Base64 should only contain valid base64 characters
    t.ok(pubKey && /^[A-Za-z0-9+/]+=*$/.test(pubKey),
        'should output valid base64')
})

test('keys command outputs in base64pad with --format base64pad', async t => {
    const result = await runCLI(['keys', 'ed25519', '-f', 'base64pad'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    const pubKey = output.publicKey

    // Base64pad should only contain valid base64 characters and end with =
    t.ok(pubKey && /^[A-Za-z0-9+/]+=*$/.test(pubKey),
        'should output valid base64pad')
    t.ok(pubKey.endsWith('='), 'should have padding')
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
    const result = await runCLIWithStdin(['encode', 'base64'], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'utf8'), 'base64')

    t.equal(output, expected, 'should correctly encode UTF-8 to base64')
})

test('encode command converts UTF-8 to base58btc by default', async t => {
    const input = 'Hello World'
    const result = await runCLIWithStdin(['encode'], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'utf8'), 'base58btc')

    t.equal(output, expected,
        'should correctly encode UTF-8 to base58btc by default')
})

test('encode command converts base64 to hex', async t => {
    const input = 'SGVsbG8gV29ybGQ='
    const result = await runCLIWithStdin([
        'encode',
        'hex',
        '--input-format',
        'base64'
    ], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'base64'), 'hex')

    t.equal(output, expected, 'should correctly convert base64 to hex')
})

test('encode command converts hex to base58btc', async t => {
    const input = '48656c6c6f'
    const result = await runCLIWithStdin([
        'encode',
        'base58btc',
        '-i',
        'hex'
    ], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'hex'), 'base58btc')

    t.equal(output, expected, 'should correctly convert hex to base58btc')
})

test('encode command converts base64url to hex', async t => {
    const input = 'SGVsbG8gV29ybGQ'
    const result = await runCLIWithStdin([
        'encode',
        'hex',
        '--input-format',
        'base64url'
    ], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'base64url'), 'hex')

    t.equal(output, expected,
        'should correctly convert base64url to hex')
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

// Test the `decode` command
test('decode command decodes base64 to UTF-8 by default', async t => {
    const input = 'SGVsbG8gV29ybGQ='
    const result = await runCLIWithStdin(['decode'], input)

    t.equal(result.code, 0, 'command should exit with code 0')
    t.equal(result.stdout.trim(), 'Hello World',
        'should correctly decode base64 to UTF-8')
})

test('decode command decodes hex to UTF-8', async t => {
    const input = '48656c6c6f20576f726c64'
    const result = await runCLIWithStdin(['decode', 'hex'], input)

    t.equal(result.code, 0, 'command should exit with code 0')
    t.equal(result.stdout.trim(), 'Hello World',
        'should correctly decode hex to UTF-8')
})

test('decode command decodes base58btc to UTF-8', async t => {
    const input = 'JxF12TrwUP45BMd'
    const result = await runCLIWithStdin(['decode', 'base58btc'], input)

    t.equal(result.code, 0, 'command should exit with code 0')
    t.equal(result.stdout.trim(), 'Hello World',
        'should correctly decode base58btc to UTF-8')
})

test('decode command decodes base64url to UTF-8', async t => {
    const input = 'SGVsbG8gV29ybGQ'
    const result = await runCLIWithStdin(['decode', 'base64url'], input)

    t.equal(result.code, 0, 'command should exit with code 0')
    t.equal(result.stdout.trim(), 'Hello World',
        'should correctly decode base64url to UTF-8')
})

test('decode command decodes base64pad to UTF-8', async t => {
    const input = 'SGVsbG8gV29ybGQ='
    const result = await runCLIWithStdin(['decode', 'base64pad'], input)

    t.equal(result.code, 0, 'command should exit with code 0')
    t.equal(result.stdout.trim(), 'Hello World',
        'should correctly decode base64pad to UTF-8')
})

test('decode command shows help with --help flag', async t => {
    const result = await runCLI(['decode', '--help'])

    t.equal(result.code, 0, 'help command should exit with code 0')
    t.ok(result.stdout.includes('Decode a string'),
        'should show command description')
    t.ok(result.stdout.includes('input-format'),
        'should mention input-format parameter')
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

/**
 * Helper function to run the CLI command with stdin input
 */
function runCLIWithStdin (args:string[], input:string):Promise<{
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

        // Write input to stdin
        child.stdin.write(input)
        child.stdin.end()
    })
}
