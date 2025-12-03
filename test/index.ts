import { test } from '@substrate-system/tapzero'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import * as u from 'uint8arrays'

const CLI_PATH = join(process.cwd(), 'dist', 'cli.js')

// Test the `keys` command
test('keys command generates Ed25519 keypair by default in raw format', async t => {
    const result = await runCLI(['keys'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    t.ok(output.publicKey, 'should have publicKey property')
    t.ok(output.privateKey, 'should have privateKey property')
    t.ok(output.publicKey.startsWith('z6Mk'),
        'public key should be in multikey format (z6Mk prefix for Ed25519)')
    t.ok(typeof output.privateKey === 'string',
        'private key should be a base64url string')
    t.ok(!output.privateKey.includes('{'),
        'private key should not be a JSON object')
})

test('keys command generates Ed25519 keypair in JWK format', async t => {
    const result = await runCLI(['keys', 'ed25519', '-f', 'jwk'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    // Should return just the private key JWK (which contains public key in 'x')
    t.equal(output.kty, 'OKP', 'should have kty OKP')
    t.equal(output.crv, 'Ed25519', 'should have crv Ed25519')
    t.ok(output.x, 'should have x (public key) component')
    t.ok(output.d, 'should have d (private key) component')
    t.ok(!output.publicKey, 'should not have separate publicKey field')
    t.ok(!output.privateKey, 'should not have separate privateKey field')
})

test('keys command generates RSA keypair with JWK format', async t => {
    const result = await runCLI(['keys', 'rsa', '-f', 'jwk'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    // Should return just the private key JWK
    t.equal(output.kty, 'RSA', 'should be RSA JWK')
    t.ok(output.d, 'should have d (private exponent)')
    t.ok(output.n, 'should have n (modulus)')
    t.ok(output.e, 'should have e (public exponent)')
    t.ok(output.p, 'should have p (first prime)')
    t.ok(output.q, 'should have q (second prime)')
    t.ok(!output.publicKey, 'should not have separate publicKey field')
    t.ok(!output.privateKey, 'should not have separate privateKey field')
})

test('keys command rejects invalid format', async t => {
    const result = await runCLI(['keys', 'ed25519', '--format', 'hex'])

    t.ok(result.code !== 0, 'should exit with non-zero code for invalid format')
    t.ok(
        (
            result.stderr.includes('Invalid values') ||
            result.stderr.includes('Choices')
        ),
        'should show error about invalid format choice'
    )
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
    t.ok(result.stdout.includes('raw'),
        'should mention raw format')
    t.ok(result.stdout.includes('jwk'),
        'should mention jwk format')
})

test('Ed25519 raw format has multikey public key and base64url private key', async t => {
    const result = await runCLI(['keys', 'ed25519'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    // Public key should be multikey format
    t.ok(output.publicKey.startsWith('z6Mk'),
        'public key should be multikey format with z6Mk prefix')

    // Private key should be base64url encoded string
    t.ok(typeof output.privateKey === 'string',
        'private key should be a string')
    t.ok(/^[A-Za-z0-9_-]+$/.test(output.privateKey),
        'private key should be valid base64url (no padding)')
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

test('encode command converts UTF-8 to base64url by default', async t => {
    const input = 'Hello World'
    const result = await runCLIWithStdin(['encode'], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = u.toString(u.fromString(input, 'utf8'), 'base64url')

    t.equal(output, expected,
        'should correctly encode UTF-8 to base64url by default')
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

// Test multibase input format
test('encode command handles multibase input with -i multi', async t => {
    // First create a multibase-encoded string
    const input = 'Hello World'
    const resultMulti = await runCLIWithStdin(
        ['encode', 'base64', '--multi'],
        input
    )

    t.equal(resultMulti.code, 0, 'multibase encode should exit with code 0')

    const multibaseString = resultMulti.stdout.trim()
    t.ok(multibaseString.startsWith('m'), 'should have base64 multibase prefix')

    // Now decode it using -i multi
    const resultDecode = await runCLIWithStdin(
        ['encode', 'hex', '-i', 'multi'],
        multibaseString
    )

    t.equal(resultDecode.code, 0, 'multibase decode should exit with code 0')

    const hexOutput = resultDecode.stdout.trim()
    const expected = u.toString(u.fromString(input, 'utf8'), 'hex')

    t.equal(hexOutput, expected, 'should correctly decode multibase input')
})

test('encode command handles base58btc multibase input', async t => {
    const input = 'zJxF12TrwUP45BMd'
    const result = await runCLIWithStdin(['encode', 'hex', '-i', 'multi'], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()
    const expected = '48656c6c6f20576f726c64'

    t.equal(output, expected, 'should correctly decode base58btc multibase to hex')
})

test('encode command handles hex multibase input', async t => {
    const input = 'f48656c6c6f20576f726c64'
    const result = await runCLIWithStdin(['encode', 'utf8', '-i', 'multi'], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()

    t.equal(output,
        'Hello World', 'should correctly decode hex multibase to utf8')
})

test('encode command handles multikey format input', async t => {
    // Generate a multikey using raw format (which outputs multikey for public key)
    const keyResult = await runCLI(['keys', 'ed25519'])
    t.equal(keyResult.code, 0, 'keys command should exit with code 0')

    const keyOutput = JSON.parse(keyResult.stdout.trim())
    const multikey = keyOutput.publicKey

    // Convert multikey to hex using -i multi
    const result = await runCLIWithStdin(
        ['encode', 'hex', '-i', 'multi'],
        multikey
    )

    t.equal(result.code, 0, 'encode command should exit with code 0')

    const hexOutput = result.stdout.trim()

    // The hex output should start with the Ed25519 multicodec prefix (ed01)
    t.ok(hexOutput.startsWith('ed01'),
        'converted multikey should start with ed01 multicodec prefix')
})

test('encode command converts hex to multi format with key type', async t => {
    // Sample hex string representing an Ed25519 public key (32 bytes)
    const input = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
    const result = await runCLIWithStdin([
        'encode',
        'multi',
        '-i',
        'hex',
        '--type',
        'ed25519'
    ], input)

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = result.stdout.trim()

    // Multi format output for Ed25519 should start with z6Mk
    t.ok(output.startsWith('z6Mk'),
        'Ed25519 multikey format should start with z6Mk prefix')
})

test('encode command requires --type when output format is multi', async t => {
    const input = '48656c6c6f20576f726c64'
    const result = await runCLIWithStdin(['encode', 'multi', '-i', 'hex'], input)

    t.ok(result.code !== 0, 'command should fail without --type')
    t.ok(result.stderr.includes('--type is required'),
        'error message should mention --type is required')
})

test('encode round-trip: multi -> hex -> multi preserves multikey', async t => {
    // Start with a known multikey (Ed25519)
    const originalMulti = 'z6Mkmy1ak2zS6hPohyNnPwMUDqpC3WE8wTR3Fcz5esUoCFNH'

    // Convert multi -> hex
    const hexResult = await runCLIWithStdin(
        ['encode', 'hex', '-i', 'multi'],
        originalMulti
    )
    t.equal(hexResult.code, 0, 'multi to hex conversion should succeed')
    const hexValue = hexResult.stdout.trim()

    // Verify hex includes the multicodec prefix
    t.ok(hexValue.startsWith('ed01'),
        'hex output should include Ed25519 multicodec prefix')

    // Convert hex -> multi
    const multiResult = await runCLIWithStdin([
        'encode',
        'multi',
        '-i',
        'hex',
        '--type',
        'ed25519'
    ], hexValue)
    t.equal(multiResult.code, 0, 'hex to multi conversion should succeed')
    const finalMulti = multiResult.stdout.trim()

    // Should match the original
    t.equal(finalMulti, originalMulti,
        'round-trip conversion should preserve the original multikey')
})

test('Ed25519 JWK has both public and private key components', async t => {
    const result = await runCLI(['keys', 'ed25519', '-f', 'jwk'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const jwk = JSON.parse(result.stdout.trim())

    t.equal(jwk.kty, 'OKP', 'should have kty OKP')
    t.equal(jwk.crv, 'Ed25519', 'should have crv Ed25519')
    t.ok(jwk.x, 'should have x (public key) component')
    t.ok(jwk.d, 'should have d (private key) component')

    // Verify the components are base64url encoded
    t.ok(/^[A-Za-z0-9_-]+$/.test(jwk.x), 'x should be base64url encoded')
    t.ok(/^[A-Za-z0-9_-]+$/.test(jwk.d), 'd should be base64url encoded')
})

test('RSA JWK contains all required components', async t => {
    const result = await runCLI(['keys', 'rsa', '-f', 'jwk'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const jwk = JSON.parse(result.stdout.trim())

    t.equal(jwk.kty, 'RSA', 'should have kty RSA')
    t.ok(jwk.n, 'should have n (modulus)')
    t.ok(jwk.e, 'should have e (public exponent)')
    t.ok(jwk.d, 'should have d (private exponent)')
    t.ok(jwk.p, 'should have p (first prime)')
    t.ok(jwk.q, 'should have q (second prime)')
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
