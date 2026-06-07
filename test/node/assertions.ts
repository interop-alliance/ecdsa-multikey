/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc.
 */
import { it, expect, beforeAll } from 'vitest'
import { base58btc as base58 } from '../../src/baseX.js'
import * as EcdsaMultikey from '../../src/index.js'
import { stringToUint8Array } from './text-encoder.js'
import { CryptoKey, webcrypto } from '../../src/crypto.js'
import { exportKeyPair } from '../../src/serialize.js'
import { getNamedCurveFromPublicMultikey } from '../../src/helpers.js'
import type { Multikey, Signer, Verifier } from '../../src/index.js'

export function testSignVerify({
  id,
  serializedKeyPair
}: {
  id: string
  serializedKeyPair: Multikey
}) {
  let signer: Signer
  let verifier: Verifier
  beforeAll(async function () {
    const keyPair = await EcdsaMultikey.from({
      id,
      ...serializedKeyPair
    })
    signer = keyPair.signer()
    verifier = keyPair.verifier()
  })
  it('should have correct id', function () {
    expect(signer).toHaveProperty('id', id)
    expect(verifier).toHaveProperty('id', id)
  })
  it('should sign & verify', async function () {
    const data = stringToUint8Array('test 1234')
    const signature = await signer.sign({ data })
    const result = await verifier.verify({ data, signature })
    expect(result).toBe(true)
  })

  it('has proper signature format', async function () {
    const data = stringToUint8Array('test 1234')
    const signature = await signer.sign({ data })
    expect(signature).toBeInstanceOf(Uint8Array)
  })

  it('fails if signing data is changed', async function () {
    const data = stringToUint8Array('test 1234')
    const signature = await signer.sign({ data })
    const changedData = stringToUint8Array('test 4321')
    const result = await verifier.verify({ data: changedData, signature })
    expect(result).toBe(false)
  })
}

export function testAlgorithm({
  serializedKeyPair,
  keyType
}: {
  serializedKeyPair: Multikey
  keyType: string
}) {
  it('signer() instance should export proper algorithm', async () => {
    const keyPair = await EcdsaMultikey.from(serializedKeyPair)
    const signer = keyPair.signer()
    expect(signer.algorithm).toBe(keyType)
  })
  it('verifier() instance should export proper algorithm', async () => {
    const keyPair = await EcdsaMultikey.from(serializedKeyPair)
    const verifier = keyPair.verifier()
    expect(verifier.algorithm).toBe(keyType)
  })
}

export function testGenerate({
  curve,
  decoder = base58,
  secretKeyByteLength = 34,
  publicKeyByteLength = 35
}: {
  curve: string
  decoder?: { decode(input: string): Uint8Array }
  secretKeyByteLength?: number
  publicKeyByteLength?: number
}) {
  it('should generate a key pair', async function () {
    let keyPair: any
    let err: any
    try {
      keyPair = await EcdsaMultikey.generate({ curve })
    } catch (e) {
      err = e
    }
    expect(err).toBeUndefined()
    expect(keyPair).toHaveProperty('publicKeyMultibase')
    expect(keyPair).toHaveProperty('secretKeyMultibase')
    expect(keyPair).toHaveProperty('publicKey')
    expect(keyPair?.publicKey instanceof CryptoKey).toBe(true)
    expect(keyPair).toHaveProperty('secretKey')
    expect(keyPair?.secretKey instanceof CryptoKey).toBe(true)
    expect(keyPair).toHaveProperty('export')
    expect(keyPair).toHaveProperty('signer')
    expect(keyPair).toHaveProperty('verifier')
    const secretKeyBytes = decoder.decode(keyPair.secretKeyMultibase.slice(1))
    const publicKeyBytes = decoder.decode(keyPair.publicKeyMultibase.slice(1))
    expect(
      secretKeyBytes.length,
      `Expected secretKey byte length to be ${secretKeyByteLength}.`
    ).toBe(secretKeyByteLength)
    expect(
      publicKeyBytes.length,
      `Expected publicKey byte length to be ${publicKeyByteLength}.`
    ).toBe(publicKeyByteLength)
  })
}

export function testExport({ curve }: { curve: string }) {
  it('should export id, type and key material', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      controller: 'did:example:1234',
      curve
    })
    const keyPairExported = await keyPair.export({
      publicKey: true,
      secretKey: true
    })

    const expectedProperties = [
      'id',
      'type',
      'controller',
      'publicKeyMultibase',
      'secretKeyMultibase'
    ]
    for (const property of expectedProperties) {
      expect(keyPairExported).toHaveProperty(property)
      expect((keyPairExported as any)[property]).toBeDefined()
    }

    expect(keyPairExported.controller).toBe('did:example:1234')
    expect(keyPairExported.type).toBe('Multikey')
    expect(keyPairExported.id).toBe('4e0db4260c87cc200df3')
  })

  it('should only export public key if specified', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      curve
    })
    const keyPairExported = await keyPair.export({ publicKey: true })

    expect(keyPairExported).not.toHaveProperty('secretKeyMultibase')
    expect(keyPairExported).toHaveProperty('publicKeyMultibase')
    expect(keyPairExported).toHaveProperty('id', '4e0db4260c87cc200df3')
    expect(keyPairExported).toHaveProperty('type', 'Multikey')
  })

  it('should only export secret key if available', async () => {
    const algorithm = { name: 'ECDSA', namedCurve: curve }
    const keyPair: any = await webcrypto.subtle.generateKey(
      algorithm as EcKeyGenParams,
      true,
      ['sign', 'verify'] as KeyUsage[]
    )
    delete keyPair.privateKey

    const keyPairExported = await exportKeyPair({
      keyPair,
      publicKey: true,
      secretKey: true,
      includeContext: true
    })

    expect(keyPairExported).not.toHaveProperty('secretKeyMultibase')
  })

  it('should export raw public key', async () => {
    const keyPair = await EcdsaMultikey.generate({ curve })
    const expectedPublicKey = base58
      .decode(keyPair.publicKeyMultibase!.slice(1))
      .slice(2)
    const { publicKey } = await keyPair.export({ publicKey: true, raw: true })
    expect(expectedPublicKey).toEqual(publicKey)
  })

  it('should export raw secret key', async () => {
    const keyPair = await EcdsaMultikey.generate({ curve })
    const expectedSecretKey = base58
      .decode(keyPair.secretKeyMultibase!.slice(1))
      .slice(2)
    const { secretKey } = await keyPair.export({ secretKey: true, raw: true })
    expect(expectedSecretKey).toEqual(secretKey)
  })
}

export function testFrom({
  serializedKeyPair,
  id,
  keyType
}: {
  serializedKeyPair: Multikey
  id: string
  keyType: string
}) {
  it('should auto-set key.id based on controller', async () => {
    const { publicKeyMultibase } = serializedKeyPair
    const keyPair = await EcdsaMultikey.from(serializedKeyPair)
    _ensurePublicKeyEncoding({ keyPair, keyType, publicKeyMultibase })
    expect(keyPair.id).toBe(id)
  })
  it('should round-trip load exported keys', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      curve: keyType
    })
    const keyPairExported = await keyPair.export({
      publicKey: true,
      secretKey: true
    })
    const keyPairImported = await EcdsaMultikey.from(keyPairExported)

    expect(
      await keyPairImported.export({ publicKey: true, secretKey: true })
    ).toEqual(keyPairExported)
  })

  it('should import with `@context` array', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      curve: keyType
    })
    const keyPairExported = await keyPair.export({
      publicKey: true,
      secretKey: true
    })
    const keyPairImported = await EcdsaMultikey.from({
      ...keyPairExported,
      '@context': [{}, keyPairExported['@context'] as string]
    })

    expect(
      await keyPairImported.export({ publicKey: true, secretKey: true })
    ).toEqual(keyPairExported)
  })
  it('should load `publicKeyJwk`', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      curve: keyType
    })
    const jwk1 = await EcdsaMultikey.toJwk({ keyPair })
    expect(jwk1.d).toBeUndefined()
    const keyPairImported1 = await EcdsaMultikey.from({ publicKeyJwk: jwk1 })
    const keyPairImported2 = await EcdsaMultikey.from({
      type: 'JsonWebKey',
      publicKeyJwk: jwk1
    })
    const jwk2 = await EcdsaMultikey.toJwk({ keyPair: keyPairImported1 })
    const jwk3 = await EcdsaMultikey.toJwk({ keyPair: keyPairImported2 })
    expect(jwk1).toEqual(jwk2)
    expect(jwk1).toEqual(jwk3)
  })
}

export function testJWK({ curve }: { curve: string }) {
  it('should round-trip secret JWKs', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      curve
    })
    const jwk1 = await EcdsaMultikey.toJwk({ keyPair, secretKey: true })
    expect(jwk1.d).toBeDefined()
    const keyPairImported = await EcdsaMultikey.fromJwk({
      jwk: jwk1,
      secretKey: true
    })
    const jwk2 = await EcdsaMultikey.toJwk({
      keyPair: keyPairImported,
      secretKey: true
    })
    expect(jwk1).toEqual(jwk2)
  })

  it('should round-trip public JWKs', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      curve
    })
    const jwk1 = await EcdsaMultikey.toJwk({ keyPair })
    expect(jwk1.d).toBeUndefined()
    const keyPairImported = await EcdsaMultikey.fromJwk({ jwk: jwk1 })
    const jwk2 = await EcdsaMultikey.toJwk({ keyPair: keyPairImported })
    expect(jwk1).toEqual(jwk2)
  })
}

export function testRaw({ curve }: { curve: string }) {
  it('should import raw public key', async () => {
    const keyPair = await EcdsaMultikey.generate({ curve })

    // first export
    const expectedPublicKey = base58
      .decode(keyPair.publicKeyMultibase!.slice(1))
      .slice(2)
    const { publicKey } = await keyPair.export({ publicKey: true, raw: true })
    expect(expectedPublicKey).toEqual(publicKey)

    // then import
    const imported = await EcdsaMultikey.fromRaw({
      curve,
      publicKey: publicKey!
    })

    // then re-export to confirm
    const { publicKey: publicKey2 } = await imported.export({
      publicKey: true,
      raw: true
    })
    expect(expectedPublicKey).toEqual(publicKey2)
  })

  it('should import raw secret key', async () => {
    const keyPair = await EcdsaMultikey.generate({ curve })

    // first export
    const expectedSecretKey = base58
      .decode(keyPair.secretKeyMultibase!.slice(1))
      .slice(2)
    const { secretKey, publicKey } = await keyPair.export({
      secretKey: true,
      raw: true
    })
    expect(expectedSecretKey).toEqual(secretKey)

    // then import
    const imported = await EcdsaMultikey.fromRaw({
      curve,
      secretKey,
      publicKey: publicKey!
    })

    // then re-export to confirm
    const { secretKey: secretKey2 } = await imported.export({
      secretKey: true,
      raw: true
    })
    expect(expectedSecretKey).toEqual(secretKey2)
  })

  it('should import raw secret key for key agreement', async () => {
    const keyPair = await EcdsaMultikey.generate({ curve, keyAgreement: true })

    // first export
    const expectedSecretKey = base58
      .decode(keyPair.secretKeyMultibase!.slice(1))
      .slice(2)
    const { secretKey, publicKey } = await keyPair.export({
      secretKey: true,
      raw: true
    })
    expect(expectedSecretKey).toEqual(secretKey)

    // then import
    const imported = await EcdsaMultikey.fromRaw({
      curve,
      secretKey,
      publicKey: publicKey!,
      keyAgreement: true
    })
    expect(imported.keyAgreement).toBe(true)

    // then re-export to confirm
    const { secretKey: secretKey2 } = await imported.export({
      secretKey: true,
      raw: true
    })
    expect(expectedSecretKey).toEqual(secretKey2)
  })
}

function _ensurePublicKeyEncoding({
  keyPair,
  publicKeyMultibase,
  keyType
}: {
  keyPair: { publicKeyMultibase?: string }
  publicKeyMultibase?: string
  keyType: string
}) {
  expect(keyPair.publicKeyMultibase!.startsWith('z')).toBe(true)
  expect(publicKeyMultibase!.startsWith('z')).toBe(true)
  const decodedPubkey = base58.decode(publicKeyMultibase!.slice(1))
  const ecdsaCurve = getNamedCurveFromPublicMultikey({
    publicMultikey: decodedPubkey
  })
  expect(ecdsaCurve).toBe(keyType)
  const encodedPubkey = 'z' + base58.encode(decodedPubkey)
  expect(encodedPubkey).toBe(keyPair.publicKeyMultibase)
}
