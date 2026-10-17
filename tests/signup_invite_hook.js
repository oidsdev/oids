/**
 * Lets the signup tests import worker/index.js. That module imports
 * ./legal.js, which is not in this tree. Signup does not use it.
 * This hook only substitutes a stub for that one import.
 */
export async function resolve(specifier, context, nextResolve) {
  const parent = context.parentURL || '';
  if (specifier === './legal.js' && parent.endsWith('/worker/index.js')) {
    return {
      shortCircuit: true,
      url: new URL('./signup_invite_legal_stub.js', import.meta.url).href,
    };
  }
  return nextResolve(specifier, context);
}
