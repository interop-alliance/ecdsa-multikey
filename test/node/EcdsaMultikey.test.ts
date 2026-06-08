/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import { describe, it, expect } from 'vitest'
import * as EcdsaMultikey from '../../src/index.js'
import {
  mockKeyEcdsaSecp256,
  mockKeyEcdsaSecp384,
  mockKeyEcdsaSecp521
} from './mock-data.js'

describe('EcdsaMultikey', () => {
  describe('module', () => {
    it('should have proper exports', async () => {
      expect(EcdsaMultikey).toHaveProperty('generate')
      expect(EcdsaMultikey).toHaveProperty('from')
      expect(EcdsaMultikey).toHaveProperty('fromJwk')
      expect(EcdsaMultikey).toHaveProperty('toJwk')
    })
  })

  describe('ECDSA_CURVE_INFO', () => {
    it('multibaseHeader should match generated public keys per curve', async () => {
      for (const info of Object.values(EcdsaMultikey.ECDSA_CURVE_INFO)) {
        const keyPair = await EcdsaMultikey.generate({ curve: info.curve })
        expect(keyPair.publicKeyMultibase?.startsWith(info.multibaseHeader)).toBe(
          true
        )
      }
    })
  })

  describe('algorithm', () => {
    it('deriveSecret() should not be supported by default', async () => {
      const keyPair = await EcdsaMultikey.generate({ curve: 'P-256' })

      let err: any
      try {
        await keyPair.deriveSecret({ publicKey: keyPair })
      } catch (e) {
        err = e
      }
      expect(err).toBeDefined()
      expect(err.name).toBe('NotSupportedError')
    })

    it('deriveSecret() should produce a shared secret', async () => {
      const keyPair1 = await EcdsaMultikey.generate({
        curve: 'P-256',
        keyAgreement: true
      })
      const keyPair2 = await EcdsaMultikey.generate({
        curve: 'P-256',
        keyAgreement: true
      })

      const secret1 = await keyPair1.deriveSecret({ publicKey: keyPair2 })
      const secret2 = await keyPair2.deriveSecret({ publicKey: keyPair1 })

      expect(secret1).toEqual(secret2)
    })
  })

  describe('from', () => {
    it('should error if publicKeyMultibase property is missing', async () => {
      let error: any
      try {
        await EcdsaMultikey.from({})
      } catch (e) {
        error = e
      }
      expect(error).toBeInstanceOf(TypeError)
      expect(error.message).toBe(
        'The "publicKeyMultibase" property is required.'
      )
    })
  })

  describe('Backwards compat with EcdsaSecp256r1VerificationKey2019', () => {
    it('Multikey should import properly', async () => {
      const keyPair = await EcdsaMultikey.from(mockKeyEcdsaSecp256)
      const data = new TextEncoder().encode('test data goes here')
      const signature = await keyPair.signer().sign({ data })

      expect(await keyPair.verifier().verify({ data, signature })).toBe(true)
    })
  })

  describe('Backwards compat with EcdsaSecp384r1VerificationKey2019', () => {
    it('Multikey should import properly', async () => {
      const keyPair = await EcdsaMultikey.from(mockKeyEcdsaSecp384)
      const data = new TextEncoder().encode('test data goes here')
      const signature = await keyPair.signer().sign({ data })

      expect(await keyPair.verifier().verify({ data, signature })).toBe(true)
    })
  })

  describe('Backwards compat with EcdsaSecp521r1VerificationKey2019', () => {
    it('Multikey should import properly', async () => {
      const keyPair = await EcdsaMultikey.from(mockKeyEcdsaSecp521)
      const data = new TextEncoder().encode('test data goes here')
      const signature = await keyPair.signer().sign({ data })

      expect(await keyPair.verifier().verify({ data, signature })).toBe(true)
    })
  })
})
