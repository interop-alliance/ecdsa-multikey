/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {
  decodeMultikey,
  MultikeyCodec
} from '@interop/data-integrity-core/multihash'
import {
  ECDSA_CURVE,
  MULTICODEC_P256_PUBLIC_KEY_HEADER,
  MULTICODEC_P256_SECRET_KEY_HEADER,
  MULTICODEC_P384_PUBLIC_KEY_HEADER,
  MULTICODEC_P384_SECRET_KEY_HEADER,
  MULTICODEC_P521_PUBLIC_KEY_HEADER,
  MULTICODEC_P521_SECRET_KEY_HEADER
} from './constants.js'
import type { EcdsaCurve } from './constants.js'

// maps a public-key multicodec identifier to its curve name
const PUBLIC_MULTIKEY_CURVES: Partial<Record<MultikeyCodec, EcdsaCurve>> = {
  [MultikeyCodec.P256_PUB]: ECDSA_CURVE.P256,
  [MultikeyCodec.P384_PUB]: ECDSA_CURVE.P384,
  [MultikeyCodec.P521_PUB]: ECDSA_CURVE.P521
}

// maps a secret-key multicodec identifier to its curve name
const SECRET_MULTIKEY_CURVES: Partial<Record<MultikeyCodec, EcdsaCurve>> = {
  [MultikeyCodec.P256_PRIV]: ECDSA_CURVE.P256,
  [MultikeyCodec.P384_PRIV]: ECDSA_CURVE.P384,
  [MultikeyCodec.P521_PRIV]: ECDSA_CURVE.P521
}

/**
 * Decodes a public Multikey string, identifying its curve. The multicodec
 * header and the compressed-point length are both validated by the
 * underlying multikey decoder.
 *
 * @param options {object}
 * @param options.publicKeyMultibase {string}
 * @returns {{ curve: EcdsaCurve, keyBytes: Uint8Array }} The curve name and
 *   the raw (compressed) public key bytes, without the multicodec header.
 */
export function decodePublicMultikey({
  publicKeyMultibase
}: {
  publicKeyMultibase: string
}): { curve: EcdsaCurve; keyBytes: Uint8Array } {
  let codec: MultikeyCodec
  let keyBytes: Uint8Array
  try {
    ;({ codec, keyBytes } = decodeMultikey({ multikey: publicKeyMultibase }))
  } catch (err) {
    throw new TypeError('Unsupported public multikey header.', { cause: err })
  }
  const curve = PUBLIC_MULTIKEY_CURVES[codec]
  if (!curve) {
    // FIXME; also support P-256K/secp256k1
    throw new TypeError('Unsupported public multikey header.')
  }
  return { curve, keyBytes }
}

/**
 * Decodes a secret Multikey string, identifying its curve. The multicodec
 * header and the secret-scalar length are both validated by the underlying
 * multikey decoder.
 *
 * @param options {object}
 * @param options.secretKeyMultibase {string}
 * @returns {{ curve: EcdsaCurve, keyBytes: Uint8Array }} The curve name and
 *   the raw secret key bytes, without the multicodec header.
 */
export function decodeSecretMultikey({
  secretKeyMultibase
}: {
  secretKeyMultibase: string
}): { curve: EcdsaCurve; keyBytes: Uint8Array } {
  let codec: MultikeyCodec
  let keyBytes: Uint8Array
  try {
    ;({ codec, keyBytes } = decodeMultikey({ multikey: secretKeyMultibase }))
  } catch (err) {
    throw new TypeError('Unsupported secret multikey header.', { cause: err })
  }
  const curve = SECRET_MULTIKEY_CURVES[codec]
  if (!curve) {
    // FIXME; also support P-256K/secp256k1
    throw new TypeError('Unsupported secret multikey header.')
  }
  return { curve, keyBytes }
}

// retrieves byte size of secret key
export function getSecretKeySize({ curve }: { curve: string }): number {
  if (curve === ECDSA_CURVE.P256) {
    return 32
  }
  if (curve === ECDSA_CURVE.P384) {
    return 48
  }
  if (curve === ECDSA_CURVE.P521) {
    return 66
  }
  throw new TypeError(`Unsupported curve "${curve}".`)
}

// sets secret key header bytes on key pair
export function setSecretKeyHeader({
  curve,
  buffer
}: {
  curve: string
  buffer: Uint8Array
}): void {
  if (curve === ECDSA_CURVE.P256) {
    buffer.set(MULTICODEC_P256_SECRET_KEY_HEADER)
  } else if (curve === ECDSA_CURVE.P384) {
    buffer.set(MULTICODEC_P384_SECRET_KEY_HEADER)
  } else if (curve === ECDSA_CURVE.P521) {
    buffer.set(MULTICODEC_P521_SECRET_KEY_HEADER)
  } else {
    throw new TypeError(`Unsupported curve "${curve}".`)
  }
}

// sets public key header bytes on key pair
export function setPublicKeyHeader({
  curve,
  buffer
}: {
  curve: string
  buffer: Uint8Array
}): void {
  if (curve === ECDSA_CURVE.P256) {
    buffer.set(MULTICODEC_P256_PUBLIC_KEY_HEADER)
  } else if (curve === ECDSA_CURVE.P384) {
    buffer.set(MULTICODEC_P384_PUBLIC_KEY_HEADER)
  } else if (curve === ECDSA_CURVE.P521) {
    buffer.set(MULTICODEC_P521_PUBLIC_KEY_HEADER)
  } else {
    throw new TypeError(`Unsupported curve "${curve}".`)
  }
}
