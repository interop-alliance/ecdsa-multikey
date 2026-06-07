/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
// Ambient type shims for dependencies that do not ship their own types.

declare module 'base58-universal' {
  export function encode(input: Uint8Array): string
  export function decode(input: string): Uint8Array
}

declare module 'base64url-universal' {
  export function encode(input: Uint8Array): string
  export function decode(input: string): Uint8Array
}
