// Resolves the worker's missing ./legal.js to the test stub.
export async function resolve(specifier, context, nextResolve) {
  const parent = context.parentURL || '';
  if (specifier === './legal.js' && parent.endsWith('/worker/index.js')) {
    return {
      shortCircuit: true,
      url: new URL('./legal-stub.mjs', import.meta.url).href,
    };
  }
  return nextResolve(specifier, context);
}
