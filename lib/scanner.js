import net from "node:net";
import { assertPublicUrl, normalizeUrl } from "./url.js";
import { scanWithYara } from "./yara-scanner.js";
import { analyzeWithUrlscan } from "./urlscan-client.js";

const PHISHING_WORDS = [
  "verify", "verification", "secure", "account", "wallet", "password",
  "signin", "login", "support", "update", "billing", "recover", "unlock"
];

function addSignal(signals, risk, points, message) {
  signals.push({ points, message });
  return Math.min(100, risk + points);
}

function extract(html, pattern) {
  return html.match(pattern)?.[1]?.replace(/\s+/g, " ").trim().slice(0, 180) || null;
}

async function readLimitedBody(response, maxBytes = 1_000_000) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let output = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      await reader.cancel();
      break;
    }
    output += decoder.decode(value, { stream: true });
  }
  return output + decoder.decode();
}

async function safeFetch(initialUrl, signal) {
  let current = initialUrl;
  for (let redirects = 0; redirects <= 3; redirects += 1) {
    await assertPublicUrl(current);
    const response = await fetch(current, {
      redirect: "manual",
      signal,
      headers: {
        "User-Agent": "SafeYou-SecurityScanner/0.1",
        "Accept": "text/html,application/xhtml+xml"
      }
    });

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) return { response, finalUrl: current, redirects };
      current = new URL(location, current).toString();
      continue;
    }
    return { response, finalUrl: current, redirects };
  }
  throw new Error("Too many redirects");
}

export async function scanUrl(input) {
  const normalized = await assertPublicUrl(input);
  const { parsed, hostname, registrableDomain, canonicalUrl } = normalized;
  const signals = [];
  let risk = 10;
  const urlscanPromise = analyzeWithUrlscan({
    url: canonicalUrl,
    domain: registrableDomain
  });

  if (parsed.protocol === "http:") {
    risk = addSignal(signals, risk, 12, "The page does not use HTTPS");
  }
  if (parsed.username || parsed.password) {
    risk = addSignal(signals, risk, 20, "The URL contains embedded credentials");
  }
  if (net.isIP(hostname)) {
    risk = addSignal(signals, risk, 18, "The site uses an IP address instead of a domain");
  }
  if (hostname.includes("xn--")) {
    risk = addSignal(signals, risk, 14, "The hostname uses internationalized characters");
  }

  const labels = hostname.split(".");
  if (labels.length > 4) {
    risk = addSignal(signals, risk, 8, "The hostname has an unusual number of subdomains");
  }
  if ((hostname.match(/-/g) || []).length >= 3) {
    risk = addSignal(signals, risk, 8, "The hostname contains many hyphens");
  }

  const urlWords = `${hostname}${parsed.pathname}`.toLowerCase();
  const keywordCount = PHISHING_WORDS.filter((word) => urlWords.includes(word)).length;
  if (keywordCount >= 2) {
    risk = addSignal(signals, risk, Math.min(15, keywordCount * 3), "The URL uses several account-related urgency terms");
  }

  const timeout = Number(process.env.SCAN_TIMEOUT_MS || 8000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  let html = "";
  let statusCode = null;
  let contentType = null;
  let fetchError = null;
  let finalUrl = canonicalUrl;
  let redirectCount = 0;
  try {
    const fetched = await safeFetch(canonicalUrl, controller.signal);
    const { response } = fetched;
    finalUrl = fetched.finalUrl;
    redirectCount = fetched.redirects;
    statusCode = response.status;
    contentType = response.headers.get("content-type") || "";
    if (contentType.includes("text/html") || contentType.includes("xhtml")) {
      html = await readLimitedBody(response);
    }
  } catch (error) {
    fetchError = error.name === "AbortError" ? "Scan timed out" : error.message;
  } finally {
    clearTimeout(timer);
  }

  const lowerHtml = html.toLowerCase();
  const finalNormalized = normalizeUrl(finalUrl);
  if (finalNormalized.registrableDomain !== registrableDomain) {
    risk = addSignal(signals, risk, 10, "The page redirects to a different registered domain");
  } else if (redirectCount > 2) {
    risk = addSignal(signals, risk, 4, "The page uses several redirects");
  }

  const formCount = (html.match(/<form\b/gi) || []).length;
  const iframeCount = (html.match(/<iframe\b/gi) || []).length;
  const passwordFieldCount = (html.match(/<input[^>]+type=["']?password/gi) || []).length;
  const externalFormActions = [...html.matchAll(/<form[^>]+action=["']([^"']+)/gi)]
    .map((match) => {
      try {
        return new URL(match[1], finalUrl);
      } catch {
        return null;
      }
    })
    .filter((url) => url && url.hostname !== finalNormalized.hostname).length;

  if (/<input[^>]+type=["']?password/i.test(html)) {
    risk = addSignal(
      signals,
      risk,
      finalNormalized.parsed.protocol === "http:" ? 24 : 8,
      "The page contains a password form"
    );
  }
  if (externalFormActions > 0) {
    risk = addSignal(signals, risk, 16, "A form submits information to another domain");
  }
  if (formCount >= 4) {
    risk = addSignal(signals, risk, 5, "The page contains an unusual number of forms");
  }
  if (/document\.location|window\.location|location\.replace/i.test(html) &&
      /atob\(|fromcharcode|eval\(/i.test(html)) {
    risk = addSignal(signals, risk, 18, "The page combines redirects with obfuscated scripts");
  }
  if (/(display\s*:\s*none|opacity\s*:\s*0)[^<]{0,120}<iframe/i.test(lowerHtml)) {
    risk = addSignal(signals, risk, 15, "The page may contain a hidden frame");
  }

  const title = extract(html, /<title[^>]*>([\s\S]*?)<\/title>/i);
  const description =
    extract(html, /<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)/i) ||
    extract(html, /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i) ||
    extract(html, /<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)/i);
  const siteName =
    extract(html, /<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']+)/i) ||
    extract(html, /<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:site_name["']/i) ||
    extract(html, /<meta[^>]+name=["']application-name["'][^>]+content=["']([^"']+)/i);

  const yara = scanWithYara(`${canonicalUrl}\n${finalUrl}\n${html}`);
  for (const match of yara.matches) {
    risk = addSignal(
      signals,
      risk,
      Math.min(35, match.severity),
      `YARA ${match.rule}: ${match.description}`
    );
  }

  const urlscan = await urlscanPromise;
  if (urlscan.result?.malicious) {
    risk = addSignal(signals, risk, 45, "urlscan.io classified the page as malicious");
  } else if ((urlscan.result?.verdictScore || 0) > 0) {
    risk = addSignal(
      signals,
      risk,
      Math.min(30, Number(urlscan.result.verdictScore)),
      `urlscan.io reported a suspicious verdict score of ${urlscan.result.verdictScore}`
    );
  }
  if ((urlscan.result?.brands || []).length > 0) {
    risk = addSignal(
      signals,
      risk,
      12,
      `urlscan.io detected possible brand targeting: ${urlscan.result.brands.join(", ")}`
    );
  }

  const analyzed = Boolean(html);
  let verdict = "unknown";
  const externallyAnalyzed = urlscan.status === "complete";
  if ((analyzed || externallyAnalyzed) && risk >= 70) verdict = "malicious";
  if (analyzed && risk <= 25 && !urlscan.result?.malicious) verdict = "safe";

  return {
    canonicalUrl,
    finalUrl: finalNormalized.canonicalUrl,
    hostname,
    registrableDomain,
    verdict,
    riskScore: risk,
    confidence: analyzed
      ? Math.min(98, 45 + signals.length * 8 + (externallyAnalyzed ? 12 : 0))
      : externallyAnalyzed ? 55 : 15,
    owner: siteName,
    title,
    description,
    statusCode,
    contentType,
    fetchError,
    pageAnalysis: {
      redirectCount,
      formCount,
      passwordFieldCount,
      iframeCount,
      externalFormActions,
      htmlBytes: Buffer.byteLength(html)
    },
    yara,
    urlscan,
    signals,
    scannedAt: new Date()
  };
}

export function publicReputation(record, source = "database") {
  return {
    url: record.canonicalUrl,
    finalUrl: record.finalUrl || record.canonicalUrl,
    hostname: record.hostname,
    verdict: record.verdict || "unknown",
    riskScore: record.riskScore ?? 50,
    confidence: record.confidence ?? 0,
    owner: record.owner || null,
    title: record.title || null,
    description: record.description || null,
    reports: record.reports || { safe: 0, malicious: 0 },
    signals: record.signals || [],
    pageAnalysis: record.pageAnalysis || null,
    yara: record.yara || { engine: "yara-x", matches: [], riskPoints: 0 },
    urlscan: record.urlscan || { status: "not-run", result: null },
    checkedAt: record.scannedAt || record.updatedAt || new Date(),
    source
  };
}
