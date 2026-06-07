/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {
  ECDSA_CURVE,
  MULTICODEC_P256_PUBLIC_KEY_HEADER,
  MULTICODEC_P256_SECRET_KEY_HEADER,
  MULTICODEC_P384_PUBLIC_KEY_HEADER,
  MULTICODEC_P384_SECRET_KEY_HEADER,
  MULTICODEC_P521_PUBLIC_KEY_HEADER,
  MULTICODEC_P521_SECRET_KEY_HEADER
} from './constants.js'

// retrieves name of appropriate ECDSA curve from public Multikey
export function getNamedCurveFromPublicMultikey({
  publicMultikey
}: {
  publicMultikey: Uint8Array
}): string {
  if (
    publicMultikey[0] === MULTICODEC_P256_PUBLIC_KEY_HEADER[0] &&
    publicMultikey[1] === MULTICODEC_P256_PUBLIC_KEY_HEADER[1]
  ) {
    return ECDSA_CURVE.P256
  }
  if (
    publicMultikey[0] === MULTICODEC_P384_PUBLIC_KEY_HEADER[0] &&
    publicMultikey[1] === MULTICODEC_P384_PUBLIC_KEY_HEADER[1]
  ) {
    return ECDSA_CURVE.P384
  }
  if (
    publicMultikey[0] === MULTICODEC_P521_PUBLIC_KEY_HEADER[0] &&
    publicMultikey[1] === MULTICODEC_P521_PUBLIC_KEY_HEADER[1]
  ) {
    return ECDSA_CURVE.P521
  }
  // FIXME; also support P-256K/secp256k1
  throw new TypeError('Unsupported public multikey header.')
}

// retrieves name of appropriate ECDSA curve from secret Multikey
export function getNamedCurveFromSecretMultikey({
  secretMultikey
}: {
  secretMultikey: Uint8Array
}): string {
  if (
    secretMultikey[0] === MULTICODEC_P256_SECRET_KEY_HEADER[0] &&
    secretMultikey[1] === MULTICODEC_P256_SECRET_KEY_HEADER[1]
  ) {
    return ECDSA_CURVE.P256
  }
  if (
    secretMultikey[0] === MULTICODEC_P384_SECRET_KEY_HEADER[0] &&
    secretMultikey[1] === MULTICODEC_P384_SECRET_KEY_HEADER[1]
  ) {
    return ECDSA_CURVE.P384
  }
  if (
    secretMultikey[0] === MULTICODEC_P521_SECRET_KEY_HEADER[0] &&
    secretMultikey[1] === MULTICODEC_P521_SECRET_KEY_HEADER[1]
  ) {
    return ECDSA_CURVE.P521
  }
  // FIXME; also support P-256K/secp256k1
  throw new TypeError('Unsupported secret multikey header.')
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
