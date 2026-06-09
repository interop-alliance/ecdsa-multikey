/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import type {
  AbstractKeyPair,
  IECPublicJWK,
  IECSecretJWK,
  ILDContext,
  IMultikeyDocument,
  IPublicJWK,
  ISecretJWK
} from '@interop/data-integrity-core'

// A WebCrypto key instance (the DOM/Node `CryptoKey`).
export type WebCryptoKey = CryptoKey

// An EC JSON Web Key, as produced and consumed by this library. Aliases the
// data-integrity-core EC JWK union: a public key (`x`, `y`) or a secret key
// (`x`, `y`, `d`).
export type JWK = IECPublicJWK | IECSecretJWK

// Internal, deliberately permissive serialization shape for a Multikey-ish key
// document: every field is optional so it can model a partially-built export or
// a legacy verification method awaiting conversion. Not part of the public API
// -- consumers should use the strict `IMultikeyDocument` / `IPublicMultikey` /
// `IMultikeyPair` from `@interop/data-integrity-core`.
export interface KeyDocument {
  '@context'?: ILDContext
  id?: string
  type?: string
  controller?: string
  revoked?: string
  publicKeyMultibase?: string
  secretKeyMultibase?: string
  // present when importing from a `JsonWebKey` / `JsonWebKey2020` type. Typed
  // permissively (any JWK) to accept the broad `publicKeyJwk` of the
  // data-integrity-core verification-method types; the ECDSA import path
  // narrows/validates it to an EC `Jwk`.
  publicKeyJwk?: IPublicJWK | ISecretJWK
}

// Options accepted by `keyPair.export()`.
export interface ExportOptions {
  publicKey?: boolean
  secretKey?: boolean
  includeContext?: boolean
  raw?: boolean
}

// The result of an `export()` call -- a Multikey, raw bytes, or both.
export type ExportedKeyPair = KeyDocument & {
  publicKey?: Uint8Array
  secretKey?: Uint8Array
}

// Options accepted by `keyPair.deriveSecret()`.
export interface DeriveSecretOptions {
  publicKey?: IECDSAKeyPair
  remotePublicKey?: IECDSAKeyPair
}

// The augmented key pair returned by `generate()`, `from()`, etc. Extends the
// shared `AbstractKeyPair` contract (`id`, `type`, `controller`, `revoked`,
// `fingerprint()`, `verifyFingerprint()`, `signer()`, `verifier()`, and the
// async `export()`) with this library's live WebCrypto key material and the
// key-agreement methods. Because `AbstractKeyPair` has no private members, the
// plain objects this library builds satisfy it structurally -- so an ecdsa key
// pair is usable anywhere an `AbstractKeyPair` is expected, without this library
// adopting a class-based design.
export interface IECDSAKeyPair extends AbstractKeyPair {
  publicKey?: WebCryptoKey
  secretKey?: WebCryptoKey
  publicKeyMultibase?: string
  secretKeyMultibase?: string
  keyAgreement?: boolean
  // Narrows the base `export()`: the default (Multikey) path returns the shared
  // `IMultikeyDocument`; the `raw` escape hatch returns key bytes.
  export(options?: ExportOptions & { raw?: false }): Promise<IMultikeyDocument>
  export(
    options: ExportOptions & { raw: true }
  ): Promise<{ publicKey?: Uint8Array; secretKey?: Uint8Array }>
  deriveSecret(options?: DeriveSecretOptions): Promise<Uint8Array>
}
