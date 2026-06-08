/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import type {
  IEcPublicJwk,
  IEcSecretJwk,
  IPublicJwk,
  ISecretJwk,
  ISigner,
  IVerifier
} from '@interop/data-integrity-core'

// A WebCrypto key instance (the DOM/Node `CryptoKey`).
export type WebCryptoKey = CryptoKey

// An EC JSON Web Key, as produced and consumed by this library. Aliases the
// data-integrity-core EC JWK union: a public key (`x`, `y`) or a secret key
// (`x`, `y`, `d`).
export type Jwk = IEcPublicJwk | IEcSecretJwk

// A `@context` value -- a single URL or an array of URLs / inline contexts.
export type JsonLdContext = string | Array<string | Record<string, unknown>>

// Internal, deliberately permissive serialization shape for a Multikey-ish key
// document: every field is optional so it can model a partially-built export or
// a legacy verification method awaiting conversion. Not part of the public API
// -- consumers should use the strict `IMultikeyDocument` / `IPublicMultikey` /
// `IMultikeyPair` from `@interop/data-integrity-core`.
export interface KeyDocument {
  '@context'?: JsonLdContext
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
  publicKeyJwk?: IPublicJwk | ISecretJwk
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
  publicKey?: KeyPairInterface
  remotePublicKey?: KeyPairInterface
}

// The augmented key pair interface returned by `generate()`, `from()`, etc.
export interface KeyPairInterface {
  '@context'?: JsonLdContext
  id?: string
  controller?: string
  type?: string
  publicKey?: WebCryptoKey
  secretKey?: WebCryptoKey
  publicKeyMultibase?: string
  secretKeyMultibase?: string
  keyAgreement?: boolean
  export(options?: ExportOptions): Promise<ExportedKeyPair>
  signer(): ISigner
  verifier(): IVerifier
  deriveSecret(options?: DeriveSecretOptions): Promise<Uint8Array>
}
