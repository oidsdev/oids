/**
 * Resolve the worker's missing ./legal.js import to tests/legal-stub.mjs.
 * Production serves legal pages from worker/legal.js; that file is not in
 * this checkout. The bio tests do not call those routes.
 */
const stub = new URL('./legal-stub.mjs', import.meta.url).href;

export async function resolve(specifier, context, nextResolve) {
  if (
    (specifier === './legal.js' || specifier.endsWith('/worker/legal.js')) &&
    context.parentURL && context.parentURL.includes('/worker/index.js')
  ) {
    return nextResolve(stub, context);
  }
  return nextResolve(specifier, context);
}
