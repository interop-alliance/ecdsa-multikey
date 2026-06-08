/*!
 * Copyright (c) 2024 Digital Bazaar, Inc.
 */
import { describe, it, expect } from 'vitest'
import * as EcdsaMultikey from '../../src/index.js'
import { createSigner, createVerifier } from '../../src/factory.js'
import {
  exportKeyPair,
  toPublicKeyBytes,
  toPublicKeyMultibase,
  toSecretKeyBytes,
  toSecretKeyMultibase
} from '../../src/serialize.js'
import {
  getNamedCurveFromPublicMultikey,
  getNamedCurveFromSecretMultikey,
  getSecretKeySize,
  setPublicKeyHeader,
  setSecretKeyHeader
} from '../../src/helpers.js'
import { MULTIKEY_CONTEXT_V1_URL } from '../../src/constants.js'
import { mockKeyEcdsaSecp256, mockKeyEcdsaSecp384 } from './mock-data.js'

const CONTEXT = MULTIKEY_CONTEXT_V1_URL

describe('error paths', () => {
  describe('generate()', () => {
    it('should default to P-256 when `curve` is omitted', async () => {
      const keyPair = await EcdsaMultikey.generate({})
      const jwk = await EcdsaMultikey.toJwk({ keyPair })
      expect(jwk.crv).toBe('P-256')
    })

    it('should throw for an unsupported `curve`', async () => {
      await expect(
        // @ts-expect-error testing an unsupported curve value
        EcdsaMultikey.generate({ curve: 'P-999' })
      ).rejects.toThrow(TypeError)
    })
  })

  describe('fromRaw()', () => {
    it('should throw if `curve` is not a string', async () => {
      await expect(
        // @ts-expect-error testing invalid input
        EcdsaMultikey.fromRaw({ publicKey: new Uint8Array(33) })
      ).rejects.toThrow('"curve" must be a string.')
    })

    it('should throw if `secretKey` is not a Uint8Array', async () => {
      await expect(
        EcdsaMultikey.fromRaw({
          curve: 'P-256',
          // @ts-expect-error testing invalid input
          secretKey: 'not-bytes',
          publicKey: new Uint8Array(33)
        })
      ).rejects.toThrow('"secretKey" must be a Uint8Array.')
    })

    it('should throw if `publicKey` is not a Uint8Array', async () => {
      await expect(
        // @ts-expect-error testing invalid input
        EcdsaMultikey.fromRaw({ curve: 'P-256', publicKey: 'not-bytes' })
      ).rejects.toThrow('"publicKey" must be a Uint8Array.')
    })

    it('should throw for an unsupported curve with a secret key', async () => {
      await expect(
        EcdsaMultikey.fromRaw({
          curve: 'P-999',
          secretKey: new Uint8Array(32),
          publicKey: new Uint8Array(33)
        })
      ).rejects.toThrow('Unsupported curve "P-999".')
    })
  })

  describe('from()', () => {
    it('should throw for an unsupported `@context`', async () => {
      await expect(
        EcdsaMultikey.from({
          type: 'Multikey',
          '@context': 'https://example.com/not-multikey/v1',
          publicKeyMultibase: mockKeyEcdsaSecp256.publicKeyMultibase
        })
      ).rejects.toThrow(/must be a Multikey with context/)
    })

    it('should throw if `publicKeyMultibase` is not base58-multibase', async () => {
      await expect(
        EcdsaMultikey.from({
          type: 'Multikey',
          '@context': CONTEXT,
          publicKeyMultibase: 'xNotMultibase'
        })
      ).rejects.toThrow(
        '"publicKeyMultibase" must be a multibase, base58-encoded string.'
      )
    })

    it('should throw if `secretKeyMultibase` is not base58-multibase', async () => {
      await expect(
        EcdsaMultikey.from({
          type: 'Multikey',
          '@context': CONTEXT,
          publicKeyMultibase: mockKeyEcdsaSecp256.publicKeyMultibase,
          secretKeyMultibase: 'xNotMultibase'
        })
      ).rejects.toThrow(
        '"secretKeyMultibase" must be a multibase, base58-encoded string.'
      )
    })

    it('should throw if public/secret key curves do not match', async () => {
      await expect(
        EcdsaMultikey.from({
          type: 'Multikey',
          '@context': CONTEXT,
          publicKeyMultibase: mockKeyEcdsaSecp256.publicKeyMultibase,
          secretKeyMultibase: mockKeyEcdsaSecp384.secretKeyMultibase
        })
      ).rejects.toThrow(/does not match/)
    })

    it('should throw for an unsupported key `type`', async () => {
      await expect(
        EcdsaMultikey.from({
          type: 'BogusVerificationKey2099',
          publicKeyMultibase: mockKeyEcdsaSecp256.publicKeyMultibase
        })
      ).rejects.toThrow('Unsupported key type "BogusVerificationKey2099".')
    })

    it('should throw for a legacy type with an unsupported `@context`', async () => {
      await expect(
        EcdsaMultikey.from({
          type: 'EcdsaSecp256r1VerificationKey2019',
          '@context': 'https://example.com/not-ecdsa-2019/v1',
          publicKeyMultibase: mockKeyEcdsaSecp256.publicKeyMultibase
        })
      ).rejects.toThrow(/Context not supported/)
    })
  })

  describe('export()', () => {
    it('should throw if neither `publicKey` nor `secretKey` requested', async () => {
      const keyPair = await EcdsaMultikey.generate({ curve: 'P-256' })
      await expect(
        keyPair.export({ publicKey: false, secretKey: false })
      ).rejects.toThrow(/either "publicKey" or "secretKey"/)
    })
  })

  describe('deriveSecret()', () => {
    it('should throw if both `publicKey` and `remotePublicKey` given', async () => {
      const keyPair = await EcdsaMultikey.generate({
        curve: 'P-256',
        keyAgreement: true
      })
      await expect(
        keyPair.deriveSecret({ publicKey: keyPair, remotePublicKey: keyPair })
      ).rejects.toThrow(/Only one of/)
    })

    it('should throw if local key pair has no secret key', async () => {
      const remote = await EcdsaMultikey.generate({
        curve: 'P-256',
        keyAgreement: true
      })
      // import a public-only key pair with key agreement enabled
      const publicOnly = await EcdsaMultikey.from(
        {
          type: 'Multikey',
          '@context': CONTEXT,
          publicKeyMultibase: mockKeyEcdsaSecp256.publicKeyMultibase
        },
        true
      )
      await expect(
        publicOnly.deriveSecret({ publicKey: remote })
      ).rejects.toThrow('"secretKey" required to derive secret.')
    })
  })

  describe('factory', () => {
    it('createSigner() should throw without a secret key', () => {
      expect(() => createSigner({})).toThrow(
        '"secretKey" is required for signing.'
      )
    })

    it('createVerifier() should throw without a public key', () => {
      expect(() => createVerifier({})).toThrow(
        '"publicKey" is required for verifying.'
      )
    })

    it('createSigner() should throw for an unsupported curve', () => {
      expect(() =>
        createSigner({
          // @ts-expect-error minimal stand-in for a WebCrypto key
          secretKey: { algorithm: { namedCurve: 'P-999' } }
        })
      ).toThrow('Unsupported curve "P-999".')
    })
  })

  describe('serialize', () => {
    it('exportKeyPair() should throw without `publicKey` or `secretKey`', async () => {
      const keyPair = await EcdsaMultikey.generate({ curve: 'P-256' })
      const imported = { publicKey: keyPair.publicKey! }
      await expect(
        exportKeyPair({ keyPair: imported, publicKey: false, secretKey: false })
      ).rejects.toThrow(/either "publicKey" or "secretKey"/)
    })

    it('to*Bytes/Multibase should throw if `jwk.kty` is not "EC"', () => {
      const jwk = { kty: 'RSA' }
      expect(() => toPublicKeyBytes({ jwk })).toThrow('"jwk.kty" must be "EC".')
      expect(() => toPublicKeyMultibase({ jwk })).toThrow(
        '"jwk.kty" must be "EC".'
      )
      expect(() => toSecretKeyBytes({ jwk })).toThrow('"jwk.kty" must be "EC".')
      expect(() => toSecretKeyMultibase({ jwk })).toThrow(
        '"jwk.kty" must be "EC".'
      )
    })
  })

  describe('helpers', () => {
    it('getNamedCurveFromPublicMultikey() should throw on bad header', () => {
      expect(() =>
        getNamedCurveFromPublicMultikey({
          publicMultikey: new Uint8Array([0x00, 0x00])
        })
      ).toThrow('Unsupported public multikey header.')
    })

    it('getNamedCurveFromSecretMultikey() should throw on bad header', () => {
      expect(() =>
        getNamedCurveFromSecretMultikey({
          secretMultikey: new Uint8Array([0x00, 0x00])
        })
      ).toThrow('Unsupported secret multikey header.')
    })

    it('getSecretKeySize() should throw for an unsupported curve', () => {
      expect(() => getSecretKeySize({ curve: 'P-999' })).toThrow(
        'Unsupported curve "P-999".'
      )
    })

    it('setSecretKeyHeader() should throw for an unsupported curve', () => {
      expect(() =>
        setSecretKeyHeader({ curve: 'P-999', buffer: new Uint8Array(2) })
      ).toThrow('Unsupported curve "P-999".')
    })

    it('setPublicKeyHeader() should throw for an unsupported curve', () => {
      expect(() =>
        setPublicKeyHeader({ curve: 'P-999', buffer: new Uint8Array(2) })
      ).toThrow('Unsupported curve "P-999".')
    })
  })
})
