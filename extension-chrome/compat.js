// Chrome exposes `chrome`; the shared extension code uses the Promise-based
// WebExtension `browser` name. Modern Manifest V3 Chrome APIs support promises.
globalThis.browser = globalThis.chrome;
