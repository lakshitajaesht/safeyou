import test from "node:test";
import assert from "node:assert/strict";
import { normalizeUrl } from "../lib/url.js";

test("normalizes URLs consistently", () => {
  const result = normalizeUrl("HTTPS://Example.COM:443/login#section");
  assert.equal(result.canonicalUrl, "https://example.com/login");
  assert.equal(result.hostname, "example.com");
});

test("rejects non-web protocols", () => {
  assert.throws(() => normalizeUrl("file:///etc/passwd"), /Only HTTP/);
});
