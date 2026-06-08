/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import type { IEcPublicJwk, IMultikeyPair } from '@interop/data-integrity-core'
import type { EcdsaCurve } from '../../src/index.js'

export const mockKey = {
  type: 'Multikey',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw',
  secretKeyMultibase: 'z42twirSb1PULt5Sg6gjgNMsdiLycu6fbA83aX1vVb8e3ncP'
}

export const mockKeyEcdsaSecp256 = {
  type: 'EcdsaSecp256r1VerificationKey2019',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw',
  secretKeyMultibase: 'z42twirSb1PULt5Sg6gjgNMsdiLycu6fbA83aX1vVb8e3ncP'
}

export const mockKeyEcdsaSecp384 = {
  type: 'Multikey',
  controller: 'did:example:1234',
  publicKeyMultibase:
    'z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4L' +
    'utoYWhvQCnGjdVn14kujQ',
  secretKeyMultibase:
    'z2fanyY7zgwNpZGxX5fXXibvScNaUWNprHU9dKx7qpVj7mws9J' +
    '8LLt4mDB5TyH2GLHWkUc'
}

export const mockKeyEcdsaSecp521 = {
  type: 'Multikey',
  controller: 'did:example:1234',
  publicKeyMultibase:
    'z2J9gaYgHvgaEEg2hB8EQMhwh4XxgRwUQdwMwnpa7P9qehd763' +
    'sEVaD9pHGqxCtKpt2xKQWX1d5XGT3GtdrwrAVxg8m9ke9R',
  secretKeyMultibase:
    'zJp6tCshdToy3U7P24S5YnDRyjCS13mKeRMevYmqVqJpraXAWT' +
    'K6vuzCXSp1hwwvgGGEnQS82ZeKaPcFDrvhWhaq4767Am'
}

const getKeyId = ({
  controller,
  publicKeyMultibase
}: {
  controller: string
  publicKeyMultibase: string
}) => `${controller}#${publicKeyMultibase}`

interface MultikeyFixture {
  id: string
  serializedKeyPair: IMultikeyPair
  props: {
    secretKeyByteLength?: number
    publicKeyByteLength?: number
  }
}

// Known-answer JWK vectors for the `mockKeyEcdsaSecp*` fixtures above.
// These are the deterministic `toJwk()` outputs for those fixed multibase
// keys; asserting against them catches base58/base64url/compression/multicodec
// header encoding regressions that the runtime round-trip tests cannot.
interface JwkVector {
  serializedKeyPair: IMultikeyPair
  publicJwk: IEcPublicJwk
  secretD: string
}

export const jwkVectors = new Map<string, JwkVector>([
  [
    'P-256',
    {
      serializedKeyPair: { ...mockKeyEcdsaSecp256, type: 'Multikey' },
      publicJwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'HKV-us2pt323YMzKrI-LzFeqznoMUSsnikhN0TARzmo',
        y: '-sCA8d_NKGBT-ZxTsM0mee1TVTuofuuqmLBhuWRGCyQ'
      },
      secretD: 'zZdIQrxZaHEIe9aAQqn6NEXf4N_ibnpWOIJsMRG29dg'
    }
  ],
  [
    'P-384',
    {
      serializedKeyPair: mockKeyEcdsaSecp384,
      publicJwk: {
        kty: 'EC',
        crv: 'P-384',
        x: '7DpOQVtOGaRWhhgCn0J_pdqai8SukuAuBqrlKGswDGTe-PDqkFWGYGSiVFFUgLwT',
        y: 'gBXZty19VyROqO-awMYhiWcIpZNn-d-59UyoSz8cnbEoiyMcOuDU_nNE_SUzJkcg'
      },
      secretD:
        'a509rS4bjBwFsZh1tmWfTeI8O2Z78pe6mqR3QHhxN9iW1XJOTHCoJfhyyepg0u31'
    }
  ],
  [
    'P-521',
    {
      serializedKeyPair: mockKeyEcdsaSecp521,
      publicJwk: {
        kty: 'EC',
        crv: 'P-521',
        x:
          'AGljPpzU_oXcDx9jyuKvwl2UlzUfbathQVfMYyHBGoKHGnliZObuh2KOV8AzI0G9' +
          'BdS6gwI4vqXHzP0m38aTR20U',
        y:
          'AJRrAg8jgh0ab7fxxztPZ5AIteKe5RdmbOeJEFO3VjxkuEQA2lhoC81dUHuMJ1YX' +
          'QIAFrsGbGkSfSaG7SmrGs6-i'
      },
      secretD:
        'AMvNrtpr4kaF29xcPgiNDyLBFis5U6TNYe5pF9lPXW-KrKIa50vVH7T0ReLxMdotR' +
        'gCEf9JZRFXuaSIsqgVKlnuW'
    }
  ]
])

export const multikeys = new Map<EcdsaCurve, MultikeyFixture>([
  [
    'P-256',
    {
      id: getKeyId(mockKeyEcdsaSecp256),
      serializedKeyPair: {
        ...mockKeyEcdsaSecp256,
        type: 'Multikey'
      },
      props: {}
    }
  ],
  [
    'P-384',
    {
      id: getKeyId(mockKeyEcdsaSecp384),
      serializedKeyPair: mockKeyEcdsaSecp384,
      props: {
        secretKeyByteLength: 50,
        publicKeyByteLength: 51
      }
    }
  ],
  [
    'P-521',
    {
      id: getKeyId(mockKeyEcdsaSecp521),
      serializedKeyPair: mockKeyEcdsaSecp521,
      props: {
        secretKeyByteLength: 68,
        publicKeyByteLength: 69
      }
    }
  ]
])
