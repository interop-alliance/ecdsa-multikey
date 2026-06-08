# @interop/ecdsa-multikey ChangeLog

## 2.2.0 - TBD

### Changed

- Use the all-caps JWK type names from `@interop/data-integrity-core`
  (`IECPublicJWK`, `IECSecretJWK`, `IPublicJWK`, `ISecretJWK`) in place of the
  now-deprecated PascalCase aliases.
- `KeyPairInterface` now extends `IKeyPairCore` from
  `@interop/data-integrity-core`, sharing the common metadata fields
  (`@context`, `id`, `type`, `controller`, `revoked`) instead of redeclaring
  them. Require `@interop/data-integrity-core@^6.4.0` (for the widened
  `IKeyPairCore['@context']`).
- Replace the local `JsonLdContext` type with the shared `ILDContext` from
  `@interop/data-integrity-core`.

## 2.1.0 - 2026-06-08

### Added

- Now depends on `@interop/data-integrity-core`, and the public API speaks its
  shared types: `signer()` / `verifier()` return `ISigner` / `IVerifier`,
  `fromJwk()` / `toJwk()` use the EC JWK types (`IEcPublicJwk` / `IEcSecretJwk`),
  and `from()` accepts the data-integrity-core verification-method types
  (`IKeyPair | IPublicKey`) in addition to this library's own `export()` output.
  Import those types from `@interop/data-integrity-core` directly.
- Exported curve-selection helpers: `ECDSA_CURVE`, `DEFAULT_ECDSA_CURVE`, the
  `EcdsaCurve` type, a per-curve metadata table `ECDSA_CURVE_INFO` (security
  level, paired hash, JOSE alg, signature size, secret-key size, and `did:key`
  multibase prefix), and `ECDSA_MULTIBASE_HEADERS` (the `did:key` prefixes for
  resolver registration).

### Changed

- **BREAKING**: `generate()` now defaults `curve` to `'P-256'` when omitted
  (previously it threw). Pass an explicit `curve` for other curves.
- **BREAKING**: this package no longer re-exports a `Multikey` type, nor
  `Signer` / `Verifier` aliases. Use `IMultikeyDocument` / `IPublicMultikey` /
  `IMultikeyPair` and `ISigner` / `IVerifier` from `@interop/data-integrity-core`.

## 2.0.0-2.0.1 - 2026-06-07

### Changed

- **BREAKING**: Forked from
  [`@digitalbazaar/ecdsa-multikey@1.8.0`](https://github.com/digitalbazaar/ecdsa-multikey)
  and published as `@interop/ecdsa-multikey`. No library behavior or public API
  changes.

### Added

- Test-only: added known-answer JWK vectors for the existing mock keys
  (asserting exact `toJwk()` encodings and `fromJwk()` round-trips), imported
  the Project Wycheproof IEEE P1363 ECDSA verification vectors for
  P-256/P-384/P-521 to exercise the verifier against externally-produced and
  malformed signatures, and added negative-path tests covering the library's
  error branches (invalid curve/multibase/JWK inputs, curve mismatches,
  unsupported key types and contexts) plus positive-path branch tests for
  optional inputs (`controller`-derived `id`, `fromJwk` `id`/`controller`,
  `includeContext`/secret-only export, array `@context`). No library behavior or
  public API changes.

### Changed

- Replaced the `base58-universal` and `base64url-universal` dependencies with
  `@scure/base` (via a small `src/baseX.ts` wrapper). No library behavior or
  public API changes.
- **Infrastructure only; no library behavior, public API, or return-shape
  changes.** Migrated the build/test toolchain to the `isomorphic-lib-template`:
  pnpm (replacing npm), Vite/Vitest for Node tests (replacing Mocha/Chai/c8),
  Playwright for the browser smoke test (replacing Karma/webpack), ESLint flat
  config + Prettier 3 (replacing `eslint-config-digitalbazaar`), and a
  single-entry `tsc` build to `dist/`.
- Converted the source from JavaScript (`lib/*.js`) to TypeScript (`src/*.ts`).
  The package now ships compiled output and type declarations from `dist/`, with
  conditional `exports`. The `node:crypto` vs `globalThis.crypto` browser swap
  is preserved via the `browser` field.
- Raised the minimum Node.js version to `>= 24`.
- The TypeScript build runs under full `strict` mode, including
  `verbatimModuleSyntax` and `noUncheckedIndexedAccess`.

## 1.8.0 - 2024-10-02

### Added

- Include `id` and `controller` properties when importing key types of
  `JsonWebKey` or `JsonWebKey2020`.

## 1.7.0 - 2024-03-17

### Added

- Add conversion from `publicKeyJwk` feature via `from()`.

### Changed

- Expect >= node 18 via `package.json`.

### Fixed

- Allow `@context` array values in multikeys.

## 1.6.0 - 2023-11-07

### Added

- Add `fromRaw()` to import a key pair from a named `curve`, `secretKey`, and
  `publicKey`.
- Reformat `keyAgreement` param in `from()` to `options` to enable named usage
  (`{keyAgreement: true|false}`) for better API.

## 1.5.0 - 2023-11-05

### Added

- Rename `remotePublicKey` param to `publicKey` for `deriveSecret()` to get
  better compatibility with WebKMS Client KeyAgreementKey interface. The param
  can still be passed as `remotePublicKey` but this is considered deprecated.

## 1.4.0 - 2023-11-05

### Added

- Add `raw` option to key pair `export()`. Based on the requested public/secret
  key, the output will include the raw bytes for the public/secret key using the
  properties `publicKey` and/or `secretKey`, respectively. The public key will
  be output using the compressed format.

## 1.3.0 - 2023-10-31

### Added

- Add `keyAgreement` option to `generate()` to generate ECDH keys instead of
  ECDSA keys. This module needs a better name than `ecdsa-multikey` as it also
  supports key agreement keys, but only for keys based on curves that are also
  compatible with ECDSA. Note that a key should only be used for ECDSA or ECDH
  (key agreement), not both, so calling this module `ecdsa-multikey` is a bit
  misleading as you can also generate a key that is to only be used for key
  agreement.
- Add `deriveSecret()` API for `keyAgreement` enabled keys.

## 1.2.1 - 2023-10-30

### Fixed

- Do not include `ext` or `key_ops` in output JWK.

## 1.2.0 - 2023-10-30

### Added

- Add `fromJwk()` and `toJwk()` for importing / exporting key pairs using JWK.

## 1.1.3 - 2023-05-19

### Fixed

- Support Node.js 20.x.

## 1.1.2 - 2023-04-14

### Fixed

- Update `.from()` method to not modify key input.

## 1.1.1 - 2023-03-11

### Fixed

- Fix data format alignment issues with ecdsa-2019-cryptosuite.
- Use constant strings in tests.

## 1.1.0 - 2023-03-06

### Changed

- Ensure public and secret multikey headers match.
- Change exported algorithm from "ECDSA" to curve name.

## 1.0.0 - 2023-02-27

### Added

- Initial version.
