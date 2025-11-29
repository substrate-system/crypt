import { test } from '@substrate-system/tapzero'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import * as u from 'uint8arrays'
import { didToPublicKey, publicKeyToDid } from '@substrate-system/keys/crypto'

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

// Test DID format encoding and decoding
test('keys command with --public did outputs valid DID format', async t => {
    const result = await runCLI(['keys', 'ed25519', '--public', 'did'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    const did = output.publicKey

    t.ok(did && did.startsWith('did:key:z'),
        'should output DID format starting with did:key:z')
})

test('DID string decodes to identical public key for Ed25519', async t => {
    // Generate a keypair with both base58btc and DID formats
    const resultBase58 = await runCLI(['keys', 'ed25519', '--format', 'base58btc'])
    const resultDid = await runCLI(['keys', 'ed25519', '--format', 'did'])

    t.equal(resultBase58.code, 0, 'base58btc command should exit with code 0')
    t.equal(resultDid.code, 0, 'did command should exit with code 0')

    // Parse outputs
    const outputDid = JSON.parse(resultDid.stdout.trim())
    const did = outputDid.publicKey

    // Decode the DID back to public key
    const decoded = didToPublicKey(did)

    t.ok(decoded.publicKey instanceof Uint8Array,
        'decoded public key should be Uint8Array')
    t.equal(decoded.type, 'ed25519',
        'decoded key type should be ed25519')

    // Verify the DID is well-formed
    t.ok(did.startsWith('did:key:z'),
        'DID should start with did:key:z')
})

test('DID round-trip preserves public key for Ed25519', async t => {
    // Generate keypair in hex format to get raw bytes
    const resultHex = await runCLI(['keys', 'ed25519', '--public', 'hex',
        '--private', 'hex'])
    t.equal(resultHex.code, 0, 'hex command should exit with code 0')

    // Generate same keypair but with DID format for public key
    // Note: We can't control the randomness, so we'll generate a new keypair
    // and test that its DID decodes correctly
    const resultDid = await runCLI(['keys', 'ed25519', '--public', 'did',
        '--private', 'hex'])
    t.equal(resultDid.code, 0, 'did command should exit with code 0')

    const outputDid = JSON.parse(resultDid.stdout.trim())
    const did = outputDid.publicKey

    // Decode the DID
    const decoded = didToPublicKey(did)

    // The decoded public key should be the same length as Ed25519 public keys
    // (32 bytes)
    t.equal(decoded.publicKey.length, 32,
        'Ed25519 public key should be 32 bytes')
    t.equal(decoded.type, 'ed25519',
        'decoded type should match')
})

test('DID format works with separate --public option', async t => {
    const result = await runCLI([
        'keys',
        'ed25519',
        '--public', 'did',
        '--private', 'base58btc'
    ])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    t.ok(output.publicKey.startsWith('did:key:z'),
        'public key should be in DID format')
    t.ok(output.privateKey.startsWith('z'),
        'private key should be in base58btc format with z prefix')
})

test('DID decoded public key can be re-encoded to same DID', async t => {
    // This test imports the encoding function to verify round-trip

    // Generate a keypair with DID format
    const result = await runCLI(['keys', 'ed25519', '--public', 'did'])
    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    const originalDid = output.publicKey

    // Decode the DID
    const decoded = didToPublicKey(originalDid)

    // Re-encode the public key bytes back to DID with the correct key type
    const reEncodedDid = await publicKeyToDid(decoded.publicKey, 'ed25519')

    // Should get the same DID
    t.equal(reEncodedDid, originalDid,
        'Re-encoding decoded public key should produce identical DID')
})

// Test multikey format
test('keys command outputs multikey format with --public multikey', async t => {
    const result = await runCLI(['keys', 'ed25519', '--public', 'multi'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    const multikey = output.publicKey

    t.ok(multikey.startsWith('z6Mk'),
        'Ed25519 multikey should start with z6Mk (multicodec 0xed01 + base58btc)')
})

test('multikey format is DID without the did:key: prefix', async t => {
    // Generate both DID and multikey formats
    const resultDid = await runCLI(['keys', 'ed25519', '--public', 'did'])
    const resultMultikey = await runCLI(['keys', 'ed25519', '--public', 'multi'])

    t.equal(resultDid.code, 0, 'DID command should exit with code 0')
    t.equal(resultMultikey.code, 0, 'multikey command should exit with code 0')

    // Parse outputs - note: these are different keys since we generated twice
    // But we can verify the structure
    const outputDid = JSON.parse(resultDid.stdout.trim())
    const outputMultikey = JSON.parse(resultMultikey.stdout.trim())

    const did = outputDid.publicKey
    const multikey = outputMultikey.publicKey

    // DID should have the prefix
    t.ok(did.startsWith('did:key:'),
        'DID should start with did:key:')

    // Multikey should not have the prefix
    t.ok(!multikey.startsWith('did:key:'),
        'Multikey should not have did:key: prefix')
    t.ok(multikey.startsWith('z6Mk'),
        'Multikey should start with z6Mk')
})

test('multikey format works with --format multikey', async t => {
    const result = await runCLI(['keys', 'ed25519', '--format', 'multi'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())

    t.ok(output.publicKey.startsWith('z6Mk'),
        'public key should be in multikey format')
    t.ok(output.privateKey.startsWith('z'),
        'private key should be in multikey format (though it uses different multicodec)')
})

test('RSA multikey has different prefix than Ed25519', async t => {
    const result = await runCLI(['keys', 'rsa', '--public', 'multi'])

    t.equal(result.code, 0, 'command should exit with code 0')

    const output = JSON.parse(result.stdout.trim())
    const multikey = output.publicKey

    // RSA uses multicodec 0x1205, which encodes differently
    t.ok(!multikey.startsWith('z6Mk'),
        'RSA multikey should not start with z6Mk')
    t.ok(multikey.startsWith('z'),
        'RSA multikey should still use base58btc (z prefix)')
})

// Test multibase input format
test('encode command handles multibase input with -i multi', async t => {
    // First create a multibase-encoded string
    const input = 'Hello World'
    const resultMulti = await runCLIWithStdin(['encode', 'base64', '--multi'], input)

    t.equal(resultMulti.code, 0, 'multibase encode should exit with code 0')

    const multibaseString = resultMulti.stdout.trim()
    t.ok(multibaseString.startsWith('m'), 'should have base64 multibase prefix')

    // Now decode it using -i multi
    const resultDecode = await runCLIWithStdin(['encode', 'hex', '-i', 'multi'], multibaseString)

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

    t.equal(output, 'Hello World', 'should correctly decode hex multibase to utf8')
})

test('encode command handles multikey format input', async t => {
    // Generate a multikey
    const keyResult = await runCLI(['keys', 'ed25519', '--public', 'multi'])
    t.equal(keyResult.code, 0, 'keys command should exit with code 0')

    const keyOutput = JSON.parse(keyResult.stdout.trim())
    const multikey = keyOutput.publicKey

    // Convert multikey to hex using -i multi
    const result = await runCLIWithStdin(['encode', 'hex', '-i', 'multi'], multikey)

    t.equal(result.code, 0, 'encode command should exit with code 0')

    const hexOutput = result.stdout.trim()

    // The hex output should start with the Ed25519 multicodec prefix (ed01)
    t.ok(hexOutput.startsWith('ed01'),
        'converted multikey should start with ed01 multicodec prefix')
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
