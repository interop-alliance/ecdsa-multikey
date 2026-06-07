/*!
 * Copyright (c) 2024 Digital Bazaar, Inc.
 */
import { describe, it, expect } from 'vitest'
import * as EcdsaMultikey from '../../src/index.js'
import { jwkVectors } from './mock-data.js'

// Known-answer tests: the `mockKey*` multibase fixtures have fixed, externally
// anchored JWK encodings. Unlike the runtime round-trip suite (which generates
// random keys and only checks self-consistency), these assert exact byte
// encodings, so they catch a consistent base58/base64url/compression/header bug
// that the round-trip tests would silently pass.
describe('JWK known-answer vectors', () => {
  for (const [curve, vector] of jwkVectors) {
    const { serializedKeyPair, publicJwk, secretD } = vector
    describe(curve, () => {
      it('toJwk() should produce the known public JWK', async () => {
        const keyPair = await EcdsaMultikey.from(serializedKeyPair)
        const jwk = await EcdsaMultikey.toJwk({ keyPair })
        expect(jwk.kty).toBe(publicJwk.kty)
        expect(jwk.crv).toBe(publicJwk.crv)
        expect(jwk.x).toBe(publicJwk.x)
        expect(jwk.y).toBe(publicJwk.y)
        expect(jwk.d).toBeUndefined()
      })

      it('toJwk() should produce the known secret JWK', async () => {
        const keyPair = await EcdsaMultikey.from(serializedKeyPair)
        const jwk = await EcdsaMultikey.toJwk({ keyPair, secretKey: true })
        expect(jwk.x).toBe(publicJwk.x)
        expect(jwk.y).toBe(publicJwk.y)
        expect(jwk.d).toBe(secretD)
      })

      it('fromJwk() should round-trip back to the known multibase', async () => {
        const jwk = {
          kty: publicJwk.kty,
          crv: publicJwk.crv,
          x: publicJwk.x,
          y: publicJwk.y,
          d: secretD
        }
        const keyPair = await EcdsaMultikey.fromJwk({ jwk, secretKey: true })
        const exported = await keyPair.export({
          publicKey: true,
          secretKey: true
        })
        expect(exported.publicKeyMultibase).toBe(
          serializedKeyPair.publicKeyMultibase
        )
        expect(exported.secretKeyMultibase).toBe(
          serializedKeyPair.secretKeyMultibase
        )
      })
    })
  }
})
