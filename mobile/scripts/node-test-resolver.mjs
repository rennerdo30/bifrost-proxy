// Resolver hook for `npm test`.
//
// The app is bundled by Metro, which resolves extensionless relative imports
// such as `./storage` against its `sourceExts`. Node's ESM resolver does not,
// so running the services under Node's built-in test runner needs the extension
// filled in. This hook does exactly that and nothing else, which keeps the app
// sources free of test-only import conventions.

import { existsSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { fileURLToPath } from 'node:url'

/** Extensions Metro would try, in the same order. */
const SOURCE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx']

/** Specifiers that already carry a module extension are left untouched. */
const HAS_EXTENSION = /\.[cm]?[jt]sx?$/

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('.') && !HAS_EXTENSION.test(specifier) && context.parentURL) {
      for (const extension of SOURCE_EXTENSIONS) {
        const candidate = new URL(specifier + extension, context.parentURL)
        if (candidate.protocol === 'file:' && existsSync(fileURLToPath(candidate))) {
          return nextResolve(specifier + extension, context)
        }
      }
    }
    return nextResolve(specifier, context)
  },
})
