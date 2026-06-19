import test from "node:test";
import assert from "node:assert/strict";
import { scanWithYara } from "../lib/yara-scanner.js";

test("YARA-X detects credential phishing language", () => {
  const result = scanWithYara(`
    <html>
      <h1>Verify your account</h1>
      <label>Password</label>
      <p>Your account will be suspended.</p>
    </html>
  `);

  assert.ok(result.matches.some((match) =>
    match.rule === "credential_phishing_language"));
  assert.ok(result.riskPoints > 0);
});

test("YARA-X leaves ordinary content unmatched", () => {
  const result = scanWithYara("<html><h1>Example documentation</h1></html>");
  assert.equal(result.matches.length, 0);
  assert.equal(result.riskPoints, 0);
});
