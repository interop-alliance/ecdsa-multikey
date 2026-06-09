/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import { base58btc as base58, base64url } from './baseX.js'
import {
  ALGORITHM,
  ECDSA_CURVE,
  EXTRACTABLE,
  MULTIBASE_BASE58_HEADER,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js'
import { webcrypto } from './crypto.js'
import {
  getNamedCurveFromPublicMultikey,
  getNamedCurveFromSecretMultikey,
  getSecretKeySize,
  setPublicKeyHeader,
  setSecretKeyHeader
} from './helpers.js'
import type { IMultikeyDocument } from '@interop/data-integrity-core'
import type { KeyDocument, WebCryptoKey } from './types.js'

// a key pair whose keys have been imported into WebCrypto
export interface ImportedKeyPair {
  id?: string
  controller?: string
  publicKey: WebCryptoKey
  secretKey?: WebCryptoKey
}

// FIXME: may need to move any leading zeros for bitstring compression; needs
// testing with various browsers
const PKCS8_PREFIXES = new Map<
  string,
  { secret: Uint8Array; public: Uint8Array }
>([
  [
    ECDSA_CURVE.P256,
    {
      secret: new Uint8Array([
        48, 103, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42,
        134, 72, 206, 61, 3, 1, 7, 4, 77, 48, 75, 2, 1, 1, 4, 32
      ]),
      public: new Uint8Array([161, 36, 3, 34, 0])
    }
  ],
  [
    ECDSA_CURVE.P384,
    {
      secret: new Uint8Array([
        48, 129, 132, 2, 1, 0, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5,
        43, 129, 4, 0, 34, 4, 109, 48, 107, 2, 1, 1, 4, 48
      ]),
      public: new Uint8Array([161, 52, 3, 50, 0])
    }
  ],
  [
    ECDSA_CURVE.P521,
    {
      secret: new Uint8Array([
        48, 129, 170, 2, 1, 0, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5,
        43, 129, 4, 0, 35, 4, 129, 146, 48, 129, 143, 2, 1, 1, 4, 66
      ]),
      public: new Uint8Array([161, 70, 3, 68, 0])
    }
  ]
])

const SPKI_PREFIXES = new Map<string, Uint8Array>([
  [
    ECDSA_CURVE.P256,
    new Uint8Array([
      48, 57, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206,
      61, 3, 1, 7, 3, 34, 0
    ])
  ],
  [
    ECDSA_CURVE.P384,
    new Uint8Array([
      48, 70, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34,
      3, 50, 0
    ])
  ],
  [
    ECDSA_CURVE.P521,
    new Uint8Array([
      48, 88, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 35,
      3, 68, 0
    ])
  ]
])

// converts key pair to PKCS #8 format
export async function cryptoKeyfromRaw({
  curve,
  secretKey,
  publicKey,
  keyAgreement
}: {
  curve: string
  secretKey?: Uint8Array
  publicKey: Uint8Array
  keyAgreement?: boolean
}): Promise<WebCryptoKey> {
  const algorithm = {
    name: keyAgreement ? 'ECDH' : ALGORITHM,
    namedCurve: curve
  }

  let cryptoKey
  if (secretKey) {
    const pkcs8 = _rawToPkcs8({ curve, secretKey, publicKey })
    const secretUsage: KeyUsage[] = keyAgreement ? ['deriveBits'] : ['sign']
    cryptoKey = await webcrypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      algorithm,
      EXTRACTABLE,
      secretUsage
    )
  } else {
    const spki = _rawToSpki({ curve, publicKey })
    // must be empty usage for importing a public key
    const publicUsage: KeyUsage[] = keyAgreement ? [] : ['verify']
    cryptoKey = await webcrypto.subtle.importKey(
      'spki',
      spki,
      algorithm,
      EXTRACTABLE,
      publicUsage
    )
  }
  return cryptoKey
}

// exports key pair
export async function exportKeyPair({
  keyPair,
  secretKey,
  publicKey,
  includeContext
}: {
  keyPair: ImportedKeyPair
  secretKey?: boolean
  publicKey?: boolean
  includeContext?: boolean
}): Promise<IMultikeyDocument> {
  if (!(publicKey || secretKey)) {
    throw new TypeError(
      'Export requires specifying either "publicKey" or "secretKey".'
    )
  }

  // get JWK
  const useSecretKey = secretKey && !!keyPair.secretKey
  const cryptoKey = useSecretKey ? keyPair.secretKey! : keyPair.publicKey
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey)

  // export as Multikey
  const exported: KeyDocument = {}
  if (includeContext) {
    exported['@context'] = MULTIKEY_CONTEXT_V1_URL
  }
  exported.id = keyPair.id
  exported.type = 'Multikey'
  exported.controller = keyPair.controller

  if (publicKey) {
    exported.publicKeyMultibase = toPublicKeyMultibase({ jwk })
  }

  if (useSecretKey) {
    exported.secretKeyMultibase = toSecretKeyMultibase({ jwk })
  }

  // Callers always request the public key (the `export()` default), so
  // `publicKeyMultibase` is set; assert the strict Multikey shape for the type.
  return exported as IMultikeyDocument
}

// imports key pair
export async function importKeyPair({
  id,
  controller,
  secretKeyMultibase,
  publicKeyMultibase,
  keyAgreement = false
}: {
  id?: string
  controller?: string
  secretKeyMultibase?: string
  publicKeyMultibase?: string
  keyAgreement?: boolean
}): Promise<ImportedKeyPair> {
  if (!publicKeyMultibase) {
    throw new TypeError('The "publicKeyMultibase" property is required.')
  }

  // import public key
  if (
    !(
      publicKeyMultibase &&
      typeof publicKeyMultibase === 'string' &&
      publicKeyMultibase[0] === MULTIBASE_BASE58_HEADER
    )
  ) {
    throw new TypeError(
      '"publicKeyMultibase" must be a multibase, base58-encoded string.'
    )
  }
  const publicMultikey = base58.decode(publicKeyMultibase.slice(1))

  // set named curved based on multikey header
  const algorithm = {
    name: keyAgreement ? 'ECDH' : ALGORITHM,
    namedCurve: getNamedCurveFromPublicMultikey({ publicMultikey })
  }

  // import public key; convert to `spki` format because `jwk` doesn't handle
  // compressed public keys
  const spki = _multikeyToSpki({ publicMultikey })
  // must be empty usage for importing a public key
  const publicUsage: KeyUsage[] = keyAgreement ? [] : ['verify']
  const importedPublicKey = await webcrypto.subtle.importKey(
    'spki',
    spki,
    algorithm,
    EXTRACTABLE,
    publicUsage
  )

  const keyPair: ImportedKeyPair = {
    id,
    controller,
    publicKey: importedPublicKey
  }

  // import secret key if given
  if (secretKeyMultibase) {
    if (
      !(
        typeof secretKeyMultibase === 'string' &&
        secretKeyMultibase[0] === MULTIBASE_BASE58_HEADER
      )
    ) {
      throw new TypeError(
        '"secretKeyMultibase" must be a multibase, base58-encoded string.'
      )
    }
    const secretMultikey = base58.decode(secretKeyMultibase.slice(1))

    // ensure secret key multikey header appropriately matches the
    // public key multikey header
    _ensureMultikeyHeadersMatch({ secretMultikey, publicMultikey })

    // convert to `pkcs8` format for import because `jwk` doesn't support
    // compressed keys
    const pkcs8 = _multikeyToPkcs8({ secretMultikey, publicMultikey })
    const secretUsage: KeyUsage[] = keyAgreement ? ['deriveBits'] : ['sign']
    keyPair.secretKey = await webcrypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      algorithm,
      EXTRACTABLE,
      secretUsage
    )
  }

  return keyPair
}

export function toPublicKeyBytes({ jwk }: { jwk: JsonWebKey }): Uint8Array {
  if (jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".')
  }
  const { crv: curve } = jwk
  const secretKeySize = getSecretKeySize({ curve: curve as string })
  // convert `x` coordinate to compressed public key
  const x = base64url.decode(jwk.x as string)
  const y = base64url.decode(jwk.y as string)
  // public key size is always secret key size + 1
  const publicKeySize = secretKeySize + 1
  const publicKey = new Uint8Array(publicKeySize)
  // use even / odd status of `y` coordinate for compressed header
  // (`y` is a decoded EC coordinate, so its last byte is always present)
  const even = y[y.length - 1]! % 2 === 0
  publicKey[0] = even ? 2 : 3
  // write `x` coordinate at end of multikey buffer to zero-fill it
  publicKey.set(x, publicKey.length - x.length)
  return publicKey
}

export function toPublicKeyMultibase({ jwk }: { jwk: JsonWebKey }): string {
  if (jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".')
  }
  const { crv: curve } = jwk
  const secretKeySize = getSecretKeySize({ curve: curve as string })
  // convert `x` coordinate to compressed public key
  const x = base64url.decode(jwk.x as string)
  const y = base64url.decode(jwk.y as string)
  // public key size is always secret key size + 1
  const publicKeySize = secretKeySize + 1
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + publicKeySize)
  setPublicKeyHeader({ curve: curve as string, buffer: multikey })
  // use even / odd status of `y` coordinate for compressed header
  // (`y` is a decoded EC coordinate, so its last byte is always present)
  const even = y[y.length - 1]! % 2 === 0
  multikey[2] = even ? 2 : 3
  // write `x` coordinate at end of multikey buffer to zero-fill it
  multikey.set(x, multikey.length - x.length)
  const publicKeyMultibase = MULTIBASE_BASE58_HEADER + base58.encode(multikey)
  return publicKeyMultibase
}

export function toSecretKeyBytes({ jwk }: { jwk: JsonWebKey }): Uint8Array {
  if (jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".')
  }
  const { crv: curve } = jwk
  const secretKeySize = getSecretKeySize({ curve: curve as string })
  const d = base64url.decode(jwk.d as string)
  const secretKey = new Uint8Array(secretKeySize)
  // write `d` at end of multikey buffer to zero-fill it
  secretKey.set(d, secretKey.length - d.length)
  return secretKey
}

export function toSecretKeyMultibase({ jwk }: { jwk: JsonWebKey }): string {
  if (jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".')
  }
  const { crv: curve } = jwk
  const secretKeySize = getSecretKeySize({ curve: curve as string })
  const d = base64url.decode(jwk.d as string)
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + secretKeySize)
  setSecretKeyHeader({ curve: jwk.crv as string, buffer: multikey })
  // write `d` at end of multikey buffer to zero-fill it
  multikey.set(d, multikey.length - d.length)
  const secretKeyMultibase = MULTIBASE_BASE58_HEADER + base58.encode(multikey)
  return secretKeyMultibase
}

// ensures that public key header matches secret key header
function _ensureMultikeyHeadersMatch({
  secretMultikey,
  publicMultikey
}: {
  secretMultikey: Uint8Array
  publicMultikey: Uint8Array
}): void {
  const publicCurve = getNamedCurveFromPublicMultikey({ publicMultikey })
  const secretCurve = getNamedCurveFromSecretMultikey({ secretMultikey })
  if (publicCurve !== secretCurve) {
    throw new Error(
      `Public key curve ('${publicCurve}') does not match ` +
        `secret key curve ('${secretCurve}').`
    )
  }
}

// converts key pair to PKCS #8 format
function _multikeyToPkcs8({
  secretMultikey,
  publicMultikey
}: {
  secretMultikey: Uint8Array
  publicMultikey: Uint8Array
}): Uint8Array<ArrayBuffer> {
  const curve = getNamedCurveFromSecretMultikey({ secretMultikey })
  // omit multikey headers
  const secretKey = secretMultikey.subarray(2)
  const publicKey = publicMultikey.subarray(2)
  return _rawToPkcs8({ curve, secretKey, publicKey })
}

function _multikeyToSpki({
  publicMultikey
}: {
  publicMultikey: Uint8Array
}): Uint8Array<ArrayBuffer> {
  const curve = getNamedCurveFromPublicMultikey({ publicMultikey })
  // omit multikey header
  const publicKey = publicMultikey.subarray(2)
  return _rawToSpki({ curve, publicKey })
}

// converts key pair to PKCS #8 format
export function _rawToPkcs8({
  curve,
  secretKey,
  publicKey
}: {
  curve: string
  secretKey: Uint8Array
  publicKey: Uint8Array
}): Uint8Array<ArrayBuffer> {
  /* Format:
  SEQUENCE (3 elem)
    INTEGER 0
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey
      // curve-specific, e.g. P-256:
      OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1
    OCTET STRING
      SEQUENCE (3 elem)
        INTEGER 1
        OCTET STRING (32 byte) (RAW SECRET KEY BYTES)
        [1] (1 elem)
          BIT STRING (COMPRESSED/UNCOMPRESSED PUBLIC KEY BYTES)

  This translates to:

  PKCS #8 DER SECRET KEY HEADER (w/algorithm OID for specific key type)
  RAW SECRET KEY BYTES
  PKCS #8 DER PUBLIC KEY HEADER
  COMPRESSED / UNCOMPRESSED PUBLIC KEY BYTES */
  const headers = PKCS8_PREFIXES.get(curve)
  if (!headers) {
    throw new Error(`Unsupported curve "${curve}".`)
  }
  const pkcs8 = new Uint8Array(
    headers.secret.length +
      secretKey.length +
      headers.public.length +
      publicKey.length
  )
  let offset = 0
  pkcs8.set(headers.secret, offset)
  offset += headers.secret.length
  pkcs8.set(secretKey, offset)
  offset += secretKey.length
  pkcs8.set(headers.public, offset)
  offset += headers.public.length
  pkcs8.set(publicKey, offset)
  return pkcs8
}

// converts public key to SubjectPublicKeyInfo format
function _rawToSpki({
  curve,
  publicKey
}: {
  curve: string
  publicKey: Uint8Array
}): Uint8Array<ArrayBuffer> {
  /* Format:
  SPKI DER PUBLIC KEY HEADER (w/algorithm OID for specific key type)
  COMPRESSED / UNCOMPRESSED PUBLIC KEY BYTES */
  const header = SPKI_PREFIXES.get(curve)!
  const spki = new Uint8Array(header.length + publicKey.length)
  let offset = 0
  spki.set(header, offset)
  offset += header.length
  spki.set(publicKey, offset)
  return spki
}
