/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {
  ALGORITHM,
  DEFAULT_ECDSA_CURVE,
  ECDSA_CURVE,
  ECDSA_CURVE_INFO,
  EXTRACTABLE,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js'
import type { EcdsaCurve } from './constants.js'
import { CryptoKey, webcrypto } from './crypto.js'
import { createSigner, createVerifier } from './factory.js'
import {
  cryptoKeyfromRaw,
  exportKeyPair,
  importKeyPair,
  toPublicKeyBytes,
  toSecretKeyBytes,
  toPublicKeyMultibase,
  toSecretKeyMultibase
} from './serialize.js'
import { getSecretKeySize } from './helpers.js'
import { toMultikey } from './translators.js'
import type {
  IKeyPair,
  IMultikeyDocument,
  IPublicKey
} from '@interop/data-integrity-core'
import type {
  DeriveSecretOptions,
  ExportOptions,
  ExportedKeyPair,
  JWK,
  KeyDocument,
  KeyPairInterface
} from './types.js'

export type {
  DeriveSecretOptions,
  ExportOptions,
  ExportedKeyPair,
  JWK,
  KeyPairInterface
} from './types.js'

// Curve selection helpers: the supported curve names, per-curve metadata
// (security level, hash, JOSE alg, signature size, did:key prefix), and the
// `did:key` multibase prefixes for resolver registration.
export {
  DEFAULT_ECDSA_CURVE,
  ECDSA_CURVE,
  ECDSA_CURVE_INFO,
  ECDSA_MULTIBASE_HEADERS
} from './constants.js'
export type { EcdsaCurve, EcdsaCurveInfo } from './constants.js'

// FIXME: support `P-256K` via `@noble/secp256k1`
// generates ECDSA key pair
export async function generate({
  id,
  controller,
  curve = DEFAULT_ECDSA_CURVE,
  keyAgreement = false
}: {
  id?: string
  controller?: string
  curve?: EcdsaCurve
  keyAgreement?: boolean
} = {}): Promise<KeyPairInterface> {
  if (!(curve in ECDSA_CURVE_INFO)) {
    throw new TypeError(
      '"curve" must be one of the following values: ' +
        `${Object.values(ECDSA_CURVE)
          .map(v => `'${v}'`)
          .join(', ')}.`
    )
  }
  const algorithm: EcKeyGenParams = keyAgreement
    ? { name: 'ECDH', namedCurve: curve }
    : { name: ALGORITHM, namedCurve: curve }
  const usage: KeyUsage[] = keyAgreement ? ['deriveBits'] : ['sign', 'verify']
  const keyPair: any = await webcrypto.subtle.generateKey(
    algorithm,
    EXTRACTABLE,
    usage
  )
  keyPair.secretKey = keyPair.privateKey
  delete keyPair.privateKey
  const keyPairInterface = await _createKeyPairInterface({
    keyPair,
    keyAgreement
  })
  const exportedKeyPair = await keyPairInterface.export({ publicKey: true })
  const { publicKeyMultibase } = exportedKeyPair
  if (controller && !id) {
    id = `${controller}#${publicKeyMultibase}`
  }
  keyPairInterface.id = id
  keyPairInterface.controller = controller
  return keyPairInterface
}

// imports P-256 key pair from JSON Multikey
export async function from(
  // accepts the data-integrity-core verification-method types, plus this
  // library's own `export()` output (`ExportedKeyPair`) for round-tripping
  key: IKeyPair | IPublicKey | ExportedKeyPair,
  options: { keyAgreement?: boolean } | boolean = {}
): Promise<KeyPairInterface> {
  // backwards compatibility
  if (typeof options === 'boolean') {
    options = { keyAgreement: options }
  }
  const { keyAgreement } = options

  let multikey: KeyDocument = { ...key }
  if (multikey.type !== 'Multikey') {
    // attempt loading from JWK if `publicKeyJwk` is present
    if (multikey.publicKeyJwk) {
      let id
      let controller
      if (
        multikey.type === 'JsonWebKey' ||
        multikey.type === 'JsonWebKey2020'
      ) {
        ;({ id, controller } = multikey)
      }
      return fromJwk({
        // the ECDSA path requires an EC JWK; `fromJwk` validates `kty`/`crv`
        jwk: multikey.publicKeyJwk as JWK,
        secretKey: false,
        id,
        controller
      })
    }
    if (multikey.type) {
      multikey = await toMultikey({ keyPair: multikey })
      return _createKeyPairInterface({ keyPair: multikey, keyAgreement })
    }
  }
  if (!multikey.type) {
    multikey.type = 'Multikey'
  }
  if (!multikey['@context']) {
    multikey['@context'] = MULTIKEY_CONTEXT_V1_URL
  }
  if (multikey.controller && !multikey.id) {
    multikey.id = `${multikey.controller}#${multikey.publicKeyMultibase}`
  }

  _assertMultikey(multikey)
  return _createKeyPairInterface({ keyPair: multikey, keyAgreement })
}

// imports key pair from JWK
export async function fromJwk(
  {
    jwk,
    secretKey = false,
    id,
    controller
  }: {
    jwk: JWK
    secretKey?: boolean
    id?: string
    controller?: string
    // accepted for backwards compatibility; `keyAgreement` is derived from the
    // JWK's `key_ops` below, so any value passed here is ignored
    keyAgreement?: boolean
  } = {} as { jwk: JWK }
): Promise<KeyPairInterface> {
  const multikey: KeyDocument = {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    type: 'Multikey',
    publicKeyMultibase: toPublicKeyMultibase({ jwk })
  }
  if (typeof id === 'string') {
    multikey.id = id
  }
  if (typeof controller === 'string') {
    multikey.controller = controller
  }
  if (secretKey && jwk.d) {
    multikey.secretKeyMultibase = toSecretKeyMultibase({ jwk })
  }
  // `key_ops` is not part of the strict EC JWK type, but WebCrypto-exported and
  // user-supplied JWKs may still carry it; read it off defensively.
  const keyOps = (jwk as { key_ops?: string[] }).key_ops
  const keyAgreement = !keyOps || keyOps.includes('deriveBits')
  // `multikey` always has `publicKeyMultibase` set above, so it satisfies the
  // strict `IMultikeyDocument` that `from()` accepts.
  return from(multikey as IMultikeyDocument, keyAgreement)
}

// converts key pair to JWK
export async function toJwk(
  {
    keyPair,
    secretKey = false
  }: {
    keyPair: any
    secretKey?: boolean
  } = {} as { keyPair: any }
): Promise<JWK> {
  if (!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair)
  }
  const useSecretKey = secretKey && !!keyPair.secretKey
  const cryptoKey = useSecretKey ? keyPair.secretKey : keyPair.publicKey
  const jwk = (await webcrypto.subtle.exportKey('jwk', cryptoKey)) as JWK
  return jwk
}

// raw import from secretKey and publicKey bytes
export async function fromRaw(
  {
    curve,
    secretKey,
    publicKey,
    keyAgreement = false
  }: {
    curve: string
    secretKey?: Uint8Array
    publicKey: Uint8Array
    keyAgreement?: boolean
  } = {} as { curve: string; publicKey: Uint8Array }
): Promise<KeyPairInterface> {
  if (typeof curve !== 'string') {
    throw new TypeError('"curve" must be a string.')
  }
  if (secretKey && !(secretKey instanceof Uint8Array)) {
    throw new TypeError('"secretKey" must be a Uint8Array.')
  }
  if (!(publicKey instanceof Uint8Array)) {
    throw new TypeError('"publicKey" must be a Uint8Array.')
  }
  const cryptoKey = await cryptoKeyfromRaw({
    curve,
    secretKey,
    publicKey,
    keyAgreement
  })
  const jwk = (await webcrypto.subtle.exportKey('jwk', cryptoKey)) as JWK
  return fromJwk({ jwk, secretKey: !!secretKey, keyAgreement })
}

// augments key pair with useful metadata and utilities
async function _createKeyPairInterface({
  keyPair,
  keyAgreement = false
}: {
  keyPair: any
  keyAgreement?: boolean
}): Promise<KeyPairInterface> {
  if (!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair)
  }
  const exportFn = async ({
    publicKey = true,
    secretKey = false,
    includeContext = true,
    raw = false
  }: ExportOptions = {}): Promise<ExportedKeyPair> => {
    if (raw) {
      const jwk = await toJwk({ keyPair, secretKey })
      const result: ExportedKeyPair = {}
      if (publicKey) {
        result.publicKey = toPublicKeyBytes({ jwk })
      }
      if (secretKey) {
        result.secretKey = toSecretKeyBytes({ jwk })
      }
      return result
    }
    return exportKeyPair({ keyPair, publicKey, secretKey, includeContext })
  }
  const { publicKeyMultibase, secretKeyMultibase } = await exportFn({
    publicKey: true,
    secretKey: true,
    includeContext: true
  })
  keyPair = {
    ...keyPair,
    publicKeyMultibase,
    secretKeyMultibase,
    keyAgreement,
    export: exportFn,
    signer() {
      const { id, secretKey } = keyPair
      return createSigner({ id, secretKey })
    },
    verifier() {
      const { id, publicKey } = keyPair
      return createVerifier({ id, publicKey })
    },
    // pass `publicKey`, as `remotePublicKey` is just a backwards compatible
    // alias
    async deriveSecret({
      publicKey,
      remotePublicKey
    }: DeriveSecretOptions = {}): Promise<Uint8Array> {
      if (remotePublicKey && publicKey) {
        throw new Error(
          'Only one of "remotePublicKey" and "publicKey" must be given.'
        )
      }
      if (!keyPair.keyAgreement) {
        const error = Error('"keyAgreement" is not supported by this keypair.')
        error.name = 'NotSupportedError'
        throw error
      }
      return _deriveSecret({
        localKeyPair: keyPair,
        remoteKeyPair: remotePublicKey || publicKey
      })
    }
  }

  return keyPair
}

// checks if key pair is in Multikey format
function _assertMultikey(key: KeyDocument): void {
  if (!(key && typeof key === 'object')) {
    throw new TypeError('"key" must be an object.')
  }
  if (key.type !== 'Multikey') {
    throw new TypeError('"key" must be a Multikey with type "Multikey".')
  }
  if (
    !(
      key['@context'] === MULTIKEY_CONTEXT_V1_URL ||
      (Array.isArray(key['@context']) &&
        key['@context'].includes(MULTIKEY_CONTEXT_V1_URL))
    )
  ) {
    throw new TypeError(
      '"key" must be a Multikey with context ' + `"${MULTIKEY_CONTEXT_V1_URL}".`
    )
  }
}

async function _deriveSecret({
  localKeyPair,
  remoteKeyPair
}: {
  localKeyPair: any
  remoteKeyPair: any
}): Promise<Uint8Array> {
  if (!localKeyPair.secretKey) {
    const error = Error('"secretKey" required to derive secret.')
    error.name = 'NotSupportedError'
    throw error
  }

  // import keys with `keyAgreement` key usage
  localKeyPair = await importKeyPair({ ...localKeyPair, keyAgreement: true })
  remoteKeyPair = await importKeyPair({ ...remoteKeyPair, keyAgreement: true })

  // produce shared secret that is the same size as a secret key, the
  // shared secret should be used as just one input to a KDF
  const { namedCurve: curve } = localKeyPair.secretKey.algorithm
  const secretSize = getSecretKeySize({ curve })
  const arrayBuffer = await webcrypto.subtle.deriveBits(
    {
      name: 'ECDH',
      namedCurve: curve,
      public: remoteKeyPair.publicKey
    } as EcdhKeyDeriveParams,
    localKeyPair.secretKey,
    secretSize * 8
  )
  return new Uint8Array(arrayBuffer, 0, secretSize)
}
