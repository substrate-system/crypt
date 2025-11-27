#!/usr/bin/env node
import 'dotenv/config'
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import * as u from 'uint8arrays'
import chalk from 'chalk'

yargs(hideBin(process.argv))
    .command(
        // command here
        'keys ...',
        'Create a new keypair',
        (yargs) => {
            return yargs
                .positional('algorithm')
        }
    )

/**
 * Generate a new keypair.
 */
async function keysCommand (args:{
    algorithm:'ed25519'|'rsa'
} = { algorithm: 'ed25519' }) {

}

/**
 * Encode a string in one format to a different format.
 */
async function encodeCommand (
    input:string,
    outputFormat:u.SupportedEncodings
):Promise<string> {

}
