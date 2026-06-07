/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import { ALGORITHM, ECDSA_CURVE, ECDSA_HASH } from './constants.js'
import { webcrypto } from './crypto.js'
import type { Signer, Verifier, WebCryptoKey } from './types.js'

// exposes sign method
export function createSigner({
  id,
  secretKey
}: {
  id?: string
  secretKey?: WebCryptoKey
}): Signer {
  if (!secretKey) {
    throw new Error('"secretKey" is required for signing.')
  }
  const { namedCurve: curve } = secretKey.algorithm as EcKeyAlgorithm
  const algorithm = {
    name: ALGORITHM,
    hash: { name: _getEcdsaHash({ curve }) }
  }
  return {
    algorithm: curve,
    id,
    async sign({ data }: { data: Uint8Array }): Promise<Uint8Array> {
      return new Uint8Array(
        await webcrypto.subtle.sign(algorithm, secretKey, data as BufferSource)
      )
    }
  }
}

// exposes verify method
export function createVerifier({
  id,
  publicKey
}: {
  id?: string
  publicKey?: WebCryptoKey
}): Verifier {
  if (!publicKey) {
    throw new Error('"publicKey" is required for verifying.')
  }
  const { namedCurve: curve } = publicKey.algorithm as EcKeyAlgorithm
  const algorithm = {
    name: ALGORITHM,
    hash: { name: _getEcdsaHash({ curve }) }
  }
  return {
    algorithm: curve,
    id,
    async verify({
      data,
      signature
    }: {
      data: Uint8Array
      signature: Uint8Array
    }): Promise<boolean> {
      return webcrypto.subtle.verify(
        algorithm,
        publicKey,
        signature as BufferSource,
        data as BufferSource
      )
    }
  }
}

// retrieves name of appropriate ECDSA hash function
function _getEcdsaHash({ curve }: { curve: string }): string {
  if (curve === ECDSA_CURVE.P256) {
    return ECDSA_HASH.SHA256
  }
  if (curve === ECDSA_CURVE.P384) {
    return ECDSA_HASH.SHA384
  }
  if (curve === ECDSA_CURVE.P521) {
    return ECDSA_HASH.SHA512
  }
  throw new TypeError(`Unsupported curve "${curve}".`)
}
