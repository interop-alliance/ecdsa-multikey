/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */

// A WebCrypto key instance (the DOM/Node `CryptoKey`).
export type WebCryptoKey = CryptoKey

// A JSON Web Key (the subset of fields used by this library).
export interface Jwk {
  kty?: string
  crv?: string
  x?: string
  y?: string
  d?: string
  key_ops?: string[]
  ext?: boolean
  [key: string]: unknown
}

// A `@context` value -- a single URL or an array of URLs / inline contexts.
export type JsonLdContext = string | Array<string | Record<string, unknown>>

// A serialized Multikey (or compatible) key object.
export interface Multikey {
  '@context'?: JsonLdContext
  id?: string
  type?: string
  controller?: string
  publicKeyMultibase?: string
  secretKeyMultibase?: string
  // present when importing from a `JsonWebKey` / `JsonWebKey2020` type
  publicKeyJwk?: Jwk
}

// A signing interface produced by `keyPair.signer()`.
export interface Signer {
  algorithm: string
  id?: string
  sign(options: { data: Uint8Array }): Promise<Uint8Array>
}

// A verification interface produced by `keyPair.verifier()`.
export interface Verifier {
  algorithm: string
  id?: string
  verify(options: { data: Uint8Array; signature: Uint8Array }): Promise<boolean>
}

// Options accepted by `keyPair.export()`.
export interface ExportOptions {
  publicKey?: boolean
  secretKey?: boolean
  includeContext?: boolean
  raw?: boolean
}

// The result of an `export()` call -- a Multikey, raw bytes, or both.
export type ExportedKeyPair = Multikey & {
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
  signer(): Signer
  verifier(): Verifier
  deriveSecret(options?: DeriveSecretOptions): Promise<Uint8Array>
}
