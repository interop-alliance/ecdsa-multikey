/*!
 * Copyright (c) 2024 Digital Bazaar, Inc.
 */
import { describe, it, expect } from 'vitest'
import * as EcdsaMultikey from '../../src/index.js'
import {
  ECDSA_2019_SUITE_CONTEXT_V1_URL,
  MULTIKEY_CONTEXT_V1_URL
} from '../../src/constants.js'
import { jwkVectors, mockKeyEcdsaSecp256 } from './mock-data.js'

// Positive-path branch coverage: optional-parameter and alternate-input paths
// that the main suite does not otherwise exercise.
describe('optional-input branches', () => {
  describe('generate()', () => {
    it('should derive `id` from `controller` when `id` is omitted', async () => {
      const controller = 'did:example:abc'
      const keyPair = await EcdsaMultikey.generate({
        curve: 'P-256',
        controller
      })
      expect(keyPair.id).toBe(`${controller}#${keyPair.publicKeyMultibase}`)
    })
  })

  describe('fromJwk()', () => {
    it('should set `id` and `controller` when provided', async () => {
      const { publicJwk } = jwkVectors.get('P-256')!
      const id = 'urn:example:key-1'
      const controller = 'did:example:xyz'
      const keyPair = await EcdsaMultikey.fromJwk({
        jwk: publicJwk,
        id,
        controller
      })
      expect(keyPair.id).toBe(id)
      expect(keyPair.controller).toBe(controller)
    })
  })

  describe('toJwk()', () => {
    it('should import a serialized Multikey before exporting', async () => {
      // `keyPair.publicKey` is not a `CryptoKey` here, so `toJwk()` must
      // import the serialized key first
      const jwk = await EcdsaMultikey.toJwk({
        keyPair: { ...mockKeyEcdsaSecp256, type: 'Multikey' }
      })
      expect(jwk.kty).toBe('EC')
      expect(jwk.crv).toBe('P-256')
    })
  })

  describe('fromRaw()', () => {
    it('should import a public-only raw key with `keyAgreement` set', async () => {
      // exercises the key-agreement public-key import path (empty key usage);
      // note the resulting `keyAgreement` flag is re-derived from the exported
      // public JWK's `key_ops`, so it is not asserted here
      const source = await EcdsaMultikey.generate({ curve: 'P-256' })
      const { publicKey } = await source.export({ publicKey: true, raw: true })
      const imported = await EcdsaMultikey.fromRaw({
        curve: 'P-256',
        publicKey: publicKey!,
        keyAgreement: true
      })
      expect(imported.publicKeyMultibase).toBe(source.publicKeyMultibase)
    })
  })

  describe('export()', () => {
    it('should omit `@context` when `includeContext` is false', async () => {
      const keyPair = await EcdsaMultikey.generate({ curve: 'P-256' })
      const exported = await keyPair.export({
        publicKey: true,
        includeContext: false
      })
      expect(exported).not.toHaveProperty('@context')
      expect(exported).toHaveProperty('publicKeyMultibase')
    })

    it('should export only the secret key when `publicKey` is false', async () => {
      const keyPair = await EcdsaMultikey.generate({ curve: 'P-256' })
      const exported = await keyPair.export({
        publicKey: false,
        secretKey: true
      })
      expect(exported).toHaveProperty('secretKeyMultibase')
      expect(exported).not.toHaveProperty('publicKeyMultibase')
    })
  })

  describe('from()', () => {
    it('should import a legacy type with an array `@context`', async () => {
      const keyPair = await EcdsaMultikey.from({
        type: 'EcdsaSecp256r1VerificationKey2019',
        '@context': [ECDSA_2019_SUITE_CONTEXT_V1_URL],
        publicKeyMultibase: mockKeyEcdsaSecp256.publicKeyMultibase,
        secretKeyMultibase: mockKeyEcdsaSecp256.secretKeyMultibase
      })
      expect(keyPair.publicKeyMultibase).toBe(
        mockKeyEcdsaSecp256.publicKeyMultibase
      )
      const exported = await keyPair.export({ publicKey: true })
      expect(exported['@context']).toBe(MULTIKEY_CONTEXT_V1_URL)
    })
  })
})
