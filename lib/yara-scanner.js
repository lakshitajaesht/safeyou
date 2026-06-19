import { readFileSync } from "node:fs";
import { compile } from "@litko/yara-x";

const rulesSource = readFileSync(
  new URL("../rules/web-threats.yar", import.meta.url),
  "utf8"
);
const compiledRules = compile(rulesSource);

export function scanWithYara(content) {
  if (!content) return { engine: "yara-x", matches: [], riskPoints: 0 };

  const matches = compiledRules.scan(Buffer.from(content));
  const findings = matches.map((match) => ({
    rule: match.ruleIdentifier,
    namespace: match.namespace,
    tags: match.tags || [],
    severity: Number(match.meta?.severity || 10),
    description: match.meta?.description || match.ruleIdentifier,
    matchedStrings: (match.matches || []).slice(0, 8).map((entry) => ({
      identifier: entry.identifier,
      offset: entry.offset,
      length: entry.length
    }))
  }));

  return {
    engine: "yara-x",
    matches: findings,
    riskPoints: Math.min(55, findings.reduce((sum, finding) => sum + finding.severity, 0))
  };
}
