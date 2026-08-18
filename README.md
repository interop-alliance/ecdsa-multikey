# EcdsaMultikey Key Pair Library for Linked Data _(@interop/ecdsa-multikey)_

[![CI](https://github.com/interop-alliance/ecdsa-multikey/actions/workflows/ci.yml/badge.svg)](https://github.com/interop-alliance/ecdsa-multikey/actions/workflows/ci.yml)
[![NPM Version](https://img.shields.io/npm/v/@interop/ecdsa-multikey.svg)](https://npm.im/@interop/ecdsa-multikey)

> TypeScript/JavaScript library for generating and working with EcdsaMultikey
> key pairs.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

(Forked from
[`digitalbazaar/ecdsa-multikey`](https://github.com/digitalbazaar/ecdsa-multikey)
to provide TypeScript compatibility.)

For use with:

- [`@digitalbazaar/ecdsa-2019-cryptosuite`](https://github.com/digitalbazaar/ecdsa-2019-cryptosuite)
  `^1.0.0` crypto suite (with
  [`jsonld-signatures`](https://github.com/digitalbazaar/jsonld-signatures)
  `^11.0.0`)
- [`@digitalbazaar/data-integrity`](https://github.com/digitalbazaar/data-integrity)
  `^1.0.0`

See also (related specs):

- [Verifiable Credential Data Integrity](https://w3c.github.io/vc-data-integrity/)

## Security

As with most security- and cryptography-related tools, the overall security of
your system will largely depend on your design decisions.

## Install

- Node.js 24+ is required.
- This package is built with [pnpm](https://pnpm.io/).

To install as a dependency:

```
npm install @interop/ecdsa-multikey
```

To install locally (for development):

```
git clone https://github.com/interop-alliance/ecdsa-multikey.git
cd ecdsa-multikey
pnpm install
```

## Usage

### Generating a new public/secret key pair

To generate a new public/secret key pair:

- `{string} [curve]` \[Required\] ECDSA curve used to generate the key:
  \['P-256', 'P-384', 'P-521'\].
- `{string} [id]` \[Optional\] ID for the generated key.
- `{string} [controller]` \[Optional\] Controller URI or DID to initialize the
  generated key. (This will be used to generate `id` if it is not explicitly
  defined.)

```js
import * as EcdsaMultikey from '@interop/ecdsa-multikey'

const keyPair = await EcdsaMultikey.generate({ curve: 'P-384' })
```

### Importing a key pair from storage

To create an instance of a public/secret key pair from data imported from
storage, use `.from()`:

```js
const serializedKeyPair = { ... };

const keyPair = await EcdsaMultikey.from(serializedKeyPair);
```

### Exporting the public key only

To export just the public key of a pair:

```js
await keyPair.export({publicKey: true});
// ->
{
  type: 'Multikey',
  id: 'did:example:1234#zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw'
}
```

### Exporting the full public-secret key pair

To export the full key pair, including secret key (warning: this should be a
carefully considered operation, best left to dedicated Key Management Systems):

```js
await keyPair.export({publicKey: true, secretKey: true});
// ->
{
  type: 'Multikey',
  id: 'did:example:1234#zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw',
  secretKeyMultibase: 'z42twirSb1PULt5Sg6gjgNMsdiLycu6fbA83aX1vVb8e3ncP'
}
```

### Creating a signer function

In order to perform a cryptographic signature, you need to create a `sign`
function, and then invoke it.

```js
const keyPair = EcdsaMultikey.generate({ curve: 'P-256' })

const { sign } = keyPair.signer()

// data is a Uint8Array of bytes
const data = new TextEncoder().encode('test data goes here')
// Signing also outputs a Uint8Array, which you can serialize to text etc.
const signature = await sign({ data })
```

### Creating a verifier function

In order to verify a cryptographic signature, you need to create a `verify`
function, and then invoke it (passing it the data to verify, and the signature).

```js
const keyPair = EcdsaMultikey.generate({ curve: 'P-521' })

const { verify } = keyPair.verifier()

const valid = await verify({ data, signature })
// true
```

## Contribute

PRs accepted.

See [CONTRIBUTING.md](CONTRIBUTING.md) -- code style and contribution
conventions.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[New BSD License (3-clause)](LICENSE) © 2023 Digital Bazaar
