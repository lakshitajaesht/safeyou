import dns from "node:dns/promises";
import net from "node:net";
import { getDomain } from "tldts";

const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal"
]);

export function normalizeUrl(input) {
  if (typeof input !== "string" || input.length > 4096) {
    throw new Error("A valid URL is required");
  }

  const parsed = new URL(input.trim());
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported");
  }

  parsed.hash = "";
  parsed.hostname = parsed.hostname.toLowerCase();
  if ((parsed.protocol === "https:" && parsed.port === "443") ||
      (parsed.protocol === "http:" && parsed.port === "80")) {
    parsed.port = "";
  }

  return {
    canonicalUrl: parsed.toString(),
    hostname: parsed.hostname,
    registrableDomain: getDomain(parsed.hostname) || parsed.hostname,
    parsed
  };
}

function isPrivateIp(address) {
  if (net.isIPv4(address)) {
    const parts = address.split(".").map(Number);
    return parts[0] === 10 ||
      parts[0] === 127 ||
      parts[0] === 0 ||
      (parts[0] === 169 && parts[1] === 254) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) ||
      parts[0] >= 224;
  }

  if (net.isIPv6(address)) {
    const value = address.toLowerCase();
    return value === "::1" ||
      value === "::" ||
      value.startsWith("fc") ||
      value.startsWith("fd") ||
      value.startsWith("fe8") ||
      value.startsWith("fe9") ||
      value.startsWith("fea") ||
      value.startsWith("feb") ||
      value.startsWith("::ffff:127.") ||
      value.startsWith("::ffff:10.") ||
      value.startsWith("::ffff:192.168.");
  }

  return true;
}

export async function assertPublicUrl(input) {
  const normalized = normalizeUrl(input);
  if (BLOCKED_HOSTS.has(normalized.hostname) || normalized.hostname.endsWith(".local")) {
    throw new Error("Private network URLs cannot be scanned");
  }

  if (net.isIP(normalized.hostname)) {
    if (isPrivateIp(normalized.hostname)) {
      throw new Error("Private network URLs cannot be scanned");
    }
    return normalized;
  }

  const addresses = await dns.lookup(normalized.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => isPrivateIp(address))) {
    throw new Error("The hostname resolves to a private or invalid address");
  }

  return normalized;
}
