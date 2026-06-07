import { test, expect } from '@playwright/test'

// Smoke test: loads the built bundle in a real browser and exercises a core
// generate + sign + verify path. This also proves the `crypto-browser` swap
// resolves in-browser (the bundle never imports `node:crypto`).
test('EcdsaMultikey generates, signs and verifies in the browser', async ({
  page
}) => {
  await page.goto('/test/index.html')
  const result = await page.evaluate(async () => {
    // @ts-expect-error -- runtime-only browser path served by Vite
    const EcdsaMultikey = await import('/dist/index.js')
    const keyPair = await EcdsaMultikey.generate({ curve: 'P-256' })
    const data = new TextEncoder().encode('test data goes here')
    const signature = await keyPair.signer().sign({ data })
    return keyPair.verifier().verify({ data, signature })
  })
  expect(result).toBe(true)
})
