/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import { webcrypto as nodeWebcrypto } from 'node:crypto'

// Use the standard (DOM) WebCrypto types so the API surface is identical in
// Node.js and the browser; the runtime implementation comes from `node:crypto`.
const webcrypto = nodeWebcrypto as unknown as Crypto
const CryptoKey =
  globalThis.CryptoKey ??
  (nodeWebcrypto as unknown as { CryptoKey: typeof globalThis.CryptoKey })
    .CryptoKey

export { CryptoKey, webcrypto }
