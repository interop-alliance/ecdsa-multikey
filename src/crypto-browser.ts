/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
export const webcrypto = globalThis.crypto
export const CryptoKey =
  globalThis.CryptoKey ??
  (webcrypto as unknown as { CryptoKey: typeof globalThis.CryptoKey }).CryptoKey
