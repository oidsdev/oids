import { register } from 'node:module';

register(new URL('./legal-stub-loader.mjs', import.meta.url).href, import.meta.url);
