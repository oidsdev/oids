// Redirect the worker's ./legal.js import at the test stub. Nothing else changes.
export async function resolve(specifier, context, nextResolve) {
  if (specifier === './legal.js' && context.parentURL && context.parentURL.endsWith('/worker/index.js')) {
    return {
      url: new URL('./legal-stub.mjs', import.meta.url).href,
      shortCircuit: true,
    };
  }
  return nextResolve(specifier, context);
}
