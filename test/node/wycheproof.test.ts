/*!
 * Copyright (c) 2024 Digital Bazaar, Inc.
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import * as EcdsaMultikey from '../../src/index.js'
import type { JWK } from '../../src/index.js'

// Project Wycheproof IEEE P1363 (raw `r||s`) ECDSA verification vectors. These
// exercise the verifier against externally-produced signatures -- including
// malleable, malformed, and edge-case `r`/`s` values -- which the runtime
// round-trip suite (sign + verify with this same library) cannot reach.
//
// The P1363 variants are used because WebCrypto's `subtle.verify` expects raw
// `r||s` signatures, so the vectors drop in without DER conversion.

interface WycheproofTest {
  tcId: number
  comment: string
  msg: string
  sig: string
  result: 'valid' | 'invalid'
  flags: string[]
}
interface WycheproofGroup {
  publicKeyJwk: JWK
  tests: WycheproofTest[]
}
interface WycheproofFile {
  source: string
  curve: string
  testGroups: WycheproofGroup[]
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function loadVectors(curve: string): WycheproofFile {
  const url = new URL(
    `./vectors/wycheproof-${curve.toLowerCase()}.json`,
    import.meta.url
  )
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8'))
}

describe('Wycheproof ECDSA P1363 verification vectors', () => {
  for (const curve of ['P-256', 'P-384', 'P-521']) {
    describe(curve, () => {
      const { testGroups } = loadVectors(curve)

      it('should agree with every vector result', async () => {
        // collect mismatches and report them together so a single failure
        // does not hide the rest
        const failures: string[] = []
        let checked = 0

        for (const group of testGroups) {
          const keyPair = await EcdsaMultikey.fromJwk({
            jwk: group.publicKeyJwk
          })
          const verifier = keyPair.verifier()

          for (const test of group.tests) {
            const data = hexToBytes(test.msg)
            const signature = hexToBytes(test.sig)
            // `subtle.verify` can reject (rather than return false) on
            // malformed inputs; a rejection means "not verified", which is
            // the correct outcome for an `invalid` vector.
            let verified: boolean
            try {
              verified = await verifier.verify({ data, signature })
            } catch {
              verified = false
            }
            const expected = test.result === 'valid'
            if (verified !== expected) {
              failures.push(
                `tcId ${test.tcId} (${test.comment}): expected ` +
                  `${test.result}, got ${verified ? 'valid' : 'invalid'}`
              )
            }
            checked++
          }
        }

        expect(checked).toBeGreaterThan(0)
        expect(failures, failures.join('\n')).toEqual([])
      })
    })
  }
})
