/*
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
// converts data from string to Uint8Array
export function stringToUint8Array(data: string | Uint8Array): Uint8Array {
  if (typeof data === 'string') {
    return new TextEncoder().encode(data)
  }
  if (!(data instanceof Uint8Array)) {
    throw new TypeError('"data" must be a string or Uint8Array.')
  }
  return data
}
