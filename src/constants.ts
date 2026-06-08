/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
// Name of algorithm
export const ALGORITHM = 'ECDSA'
// Determines whether key pair is extractable
export const EXTRACTABLE = true
// ECDSA curve P-256 type
export const ECDSA_2019_SECP_256_KEY_TYPE = 'EcdsaSecp256r1VerificationKey2019'
// ECDSA curve P-384 type
export const ECDSA_2019_SECP_384_KEY_TYPE = 'EcdsaSecp384r1VerificationKey2019'
// ECDSA curve P-521 type
export const ECDSA_2019_SECP_521_KEY_TYPE = 'EcdsaSecp521r1VerificationKey2019'
// ECDSA 2019 suite context v1 URL
export const ECDSA_2019_SUITE_CONTEXT_V1_URL =
  'https://w3id.org/security/suites/ecdsa-2019/v1'
// Multikey context v1 URL
export const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1'
export const MULTIBASE_BASE58_HEADER = 'z'

// Multicodec p256-pub header (0x1200 varint -> 0x8024 hex)
export const MULTICODEC_P256_PUBLIC_KEY_HEADER = new Uint8Array([0x80, 0x24])
// Multicodec p384-pub header (0x1201 varint -> 0x8124 hex)
export const MULTICODEC_P384_PUBLIC_KEY_HEADER = new Uint8Array([0x81, 0x24])
// Multicodec p521-pub header (0x1202 varint -> 0x8224 hex)
export const MULTICODEC_P521_PUBLIC_KEY_HEADER = new Uint8Array([0x82, 0x24])

// Multicodec p256-priv header (0x1306 varint -> 0x8626 hex)
export const MULTICODEC_P256_SECRET_KEY_HEADER = new Uint8Array([0x86, 0x26])
// Multicodec p384-priv header (0x1307 varint -> 0x8726 hex)
export const MULTICODEC_P384_SECRET_KEY_HEADER = new Uint8Array([0x87, 0x26])
// Multicodec p521-priv header (0x1308 varint -> 0x8826 hex)
export const MULTICODEC_P521_SECRET_KEY_HEADER = new Uint8Array([0x88, 0x26])

// ECDSA curves
export const ECDSA_CURVE = {
  P256: 'P-256',
  P384: 'P-384',
  P521: 'P-521'
} as const

// ECDSA hash functions
export const ECDSA_HASH = {
  SHA256: 'SHA-256',
  SHA384: 'SHA-384',
  SHA512: 'SHA-512'
} as const

// An ECDSA curve name supported by this library.
export type EcdsaCurve = (typeof ECDSA_CURVE)[keyof typeof ECDSA_CURVE]

// The default curve used by `generate()` when none is specified. P-256 has the
// broadest interop and best performance; choose a larger curve only when a
// policy/compliance requirement (e.g. CNSA mandates P-384) calls for it.
export const DEFAULT_ECDSA_CURVE: EcdsaCurve = ECDSA_CURVE.P256

// Per-curve metadata, to help callers pick and consume a curve.
export interface EcdsaCurveInfo {
  // NIST/SECG curve name -- the value used for WebCrypto `namedCurve` and read
  // off a signer/verifier as `algorithm` by the ecdsa-rdfc-2019 cryptosuite.
  curve: EcdsaCurve
  // Approximate classical security level, in bits.
  securityBits: 128 | 192 | 256
  // Digest paired with this curve (commensurate strength), as a WebCrypto hash
  // name.
  hash: 'SHA-256' | 'SHA-384' | 'SHA-512'
  // JOSE / COSE algorithm identifier (RFC 7518).
  jose: 'ES256' | 'ES384' | 'ES512'
  // Raw (IEEE P1363 `r||s`) signature size in bytes -- the form WebCrypto emits.
  signatureSize: 64 | 96 | 132
  // Secret scalar `d` size, in bytes.
  secretKeySize: 32 | 48 | 66
  // 4-character multibase-multikey prefix of a `did:key` public key for this
  // curve -- e.g. for registering the suite with `@interop/did-method-key`.
  multibaseHeader: 'zDna' | 'z82L' | 'z2J9'
}

// Metadata for every ECDSA curve this library supports. See `EcdsaCurveInfo`.
export const ECDSA_CURVE_INFO: Record<EcdsaCurve, EcdsaCurveInfo> = {
  [ECDSA_CURVE.P256]: {
    curve: ECDSA_CURVE.P256,
    securityBits: 128,
    hash: ECDSA_HASH.SHA256,
    jose: 'ES256',
    signatureSize: 64,
    secretKeySize: 32,
    multibaseHeader: 'zDna'
  },
  [ECDSA_CURVE.P384]: {
    curve: ECDSA_CURVE.P384,
    securityBits: 192,
    hash: ECDSA_HASH.SHA384,
    jose: 'ES384',
    signatureSize: 96,
    secretKeySize: 48,
    multibaseHeader: 'z82L'
  },
  [ECDSA_CURVE.P521]: {
    curve: ECDSA_CURVE.P521,
    securityBits: 256,
    hash: ECDSA_HASH.SHA512,
    jose: 'ES512',
    signatureSize: 132,
    secretKeySize: 66,
    multibaseHeader: 'z2J9'
  }
}

// All `did:key` multibase-multikey prefixes for ECDSA keys (one per curve),
// e.g. to register every ECDSA curve with a `did:key` resolver.
export const ECDSA_MULTIBASE_HEADERS = [
  ECDSA_CURVE_INFO[ECDSA_CURVE.P256].multibaseHeader,
  ECDSA_CURVE_INFO[ECDSA_CURVE.P384].multibaseHeader,
  ECDSA_CURVE_INFO[ECDSA_CURVE.P521].multibaseHeader
] as const
